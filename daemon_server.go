package provider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	acquisitionDaemonSchemaVersion = 2
	acquisitionDaemonIdleLifetime  = 20 * time.Second
	acquisitionDaemonResponseMax   = maxResponseBytes
	acquisitionDaemonAuthTimeout   = 5 * time.Second
)

type acquisitionDaemonEndpoint struct {
	SchemaVersion int    `json:"schema_version"`
	Address       string `json:"address"`
	Transport     string `json:"transport"`
	Token         string `json:"token"`
	PID           int    `json:"pid"`
	Version       string `json:"version"`
	ProviderPath  string `json:"provider_path"`
	DaemonPath    string `json:"daemon_path,omitempty"`
	ClientPath    string `json:"client_path"`
	StartedAt     string `json:"started_at"`
}

type acquisitionDaemonRequest struct {
	SchemaVersion int             `json:"schema_version"`
	Token         string          `json:"token"`
	Command       string          `json:"command"`
	Acquire       *acquireRequest `json:"acquire,omitempty"`
}

type acquisitionDaemonError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type acquisitionDaemonResponse struct {
	SchemaVersion int                     `json:"schema_version"`
	Status        string                  `json:"status,omitempty"`
	Result        *response               `json:"result,omitempty"`
	Error         *acquisitionDaemonError `json:"error,omitempty"`
}

func randomDaemonToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	defer zeroBytes(raw)
	return hex.EncodeToString(raw), nil
}

func validateDaemonEndpointPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("daemon endpoint path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("daemon endpoint path is invalid")
	}
	parent := filepath.Dir(absolute)
	info, err := os.Lstat(parent)
	unsafeParent := false
	if err == nil {
		unsafeParent, err = pathIsLinkOrReparse(parent, info.Mode())
	}
	if err != nil || !info.IsDir() || unsafeParent {
		return "", errors.New("daemon endpoint parent is not a trusted directory")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || !sameCanonicalPath(parent, resolved) {
		return "", errors.New("daemon endpoint parent contains a link")
	}
	if err := validateDaemonDirectorySecurity(parent); err != nil {
		return "", err
	}
	if existing, statErr := os.Lstat(absolute); statErr == nil {
		unsafeEndpoint, safetyErr := pathIsLinkOrReparse(absolute, existing.Mode())
		if safetyErr != nil || unsafeEndpoint || !existing.Mode().IsRegular() {
			return "", errors.New("daemon endpoint cannot be a link or reparse point")
		}
	} else if !os.IsNotExist(statErr) {
		return "", errors.New("daemon endpoint cannot be inspected")
	}
	return absolute, nil
}

func writeDaemonEndpoint(path string, endpoint acquisitionDaemonEndpoint) error {
	payload, err := json.MarshalIndent(endpoint, "", "  ")
	if err != nil {
		return err
	}
	markSensitiveBytes(payload)
	defer zeroBytes(payload)
	file, err := os.CreateTemp(filepath.Dir(path), ".acquisition-endpoint-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if _, err := io.WriteString(file, "\n"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	remove = false
	return nil
}

func removeDaemonEndpoint(path, token string) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return
	}
	markSensitiveBytes(payload)
	defer zeroBytes(payload)
	var current acquisitionDaemonEndpoint
	if json.Unmarshal(payload, &current) == nil && subtle.ConstantTimeCompare([]byte(current.Token), []byte(token)) == 1 {
		_ = os.Remove(path)
	}
}

func daemonFailure(code, message string) acquisitionDaemonResponse {
	return acquisitionDaemonResponse{
		SchemaVersion: acquisitionDaemonSchemaVersion,
		Error:         &acquisitionDaemonError{Code: code, Message: message},
	}
}

func writeAcquisitionDaemonResponse(connection net.Conn, result acquisitionDaemonResponse) {
	payload, err := json.Marshal(result)
	if err != nil || len(payload)+1 > acquisitionDaemonResponseMax {
		payload, _ = json.Marshal(daemonFailure("response_too_large", "daemon response exceeded the safety limit"))
	}
	markSensitiveBytes(payload)
	defer zeroBytes(payload)
	_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.Copy(connection, bytes.NewReader(payload))
	_, _ = io.WriteString(connection, "\n")
}

func handleAcquisitionDaemonConnection(connection net.Conn, endpoint acquisitionDaemonEndpoint, store *acquisitionSessionStore) bool {
	defer connection.Close()
	peerIdentity, peerErr := verifyAcquisitionDaemonPeer(connection, endpoint.Transport, endpoint.ClientPath)
	if peerErr != nil {
		writeAcquisitionDaemonResponse(connection, daemonFailure("unauthorized_peer", "daemon client identity verification failed"))
		return false
	}
	// 身份验证只是短暂的帧解析操作。只有令牌和请求通过验证后才启用获取时限，避免未经
	// 身份验证的回环连接长时间独占守护进程。
	_ = connection.SetReadDeadline(time.Now().Add(acquisitionDaemonAuthTimeout))
	reader := bufio.NewReaderSize(connection, maxRequestBytes+1)
	payload, err := reader.ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		writeAcquisitionDaemonResponse(connection, daemonFailure("invalid_request", "daemon request is empty or too large"))
		return false
	}
	if len(payload) == 0 || len(payload) > maxRequestBytes {
		writeAcquisitionDaemonResponse(connection, daemonFailure("invalid_request", "daemon request is empty or too large"))
		return false
	}
	markSensitiveBytes(payload)
	defer zeroBytes(payload)
	var request acquisitionDaemonRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeAcquisitionDaemonResponse(connection, daemonFailure("invalid_request", "daemon request is invalid"))
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeAcquisitionDaemonResponse(connection, daemonFailure("invalid_request", "daemon request contains trailing data"))
		return false
	}
	if request.SchemaVersion != acquisitionDaemonSchemaVersion || len(request.Token) != 64 ||
		subtle.ConstantTimeCompare([]byte(request.Token), []byte(endpoint.Token)) != 1 {
		writeAcquisitionDaemonResponse(connection, daemonFailure("unauthorized", "daemon authentication failed"))
		return false
	}
	switch request.Command {
	case "ping":
		writeAcquisitionDaemonResponse(connection, acquisitionDaemonResponse{SchemaVersion: acquisitionDaemonSchemaVersion, Status: "ready"})
	case "shutdown":
		writeAcquisitionDaemonResponse(connection, acquisitionDaemonResponse{SchemaVersion: acquisitionDaemonSchemaVersion, Status: "stopping"})
		return true
	case "acquire":
		if request.Acquire == nil {
			writeAcquisitionDaemonResponse(connection, daemonFailure("invalid_request", "acquire request is missing"))
			return false
		}
		encoded, err := json.Marshal(request.Acquire)
		if err != nil {
			writeAcquisitionDaemonResponse(connection, daemonFailure("invalid_request", "acquire request cannot be encoded"))
			return false
		}
		markSensitiveBytes(encoded)
		defer zeroBytes(encoded)
		validated, err := decodeRequestData(encoded)
		if err != nil {
			writeAcquisitionDaemonResponse(connection, daemonFailure("invalid_request", "acquire request failed validation"))
			return false
		}
		validated.PeerIdentity = peerIdentity
		_ = connection.SetReadDeadline(time.Time{})
		requestContext, cancelRequest := context.WithCancel(context.Background())
		defer cancelRequest()
		// 每条连接只接受一个请求。身份验证帧完成后，遇到 EOF 表示 CLI 已退出；所有扫描
		// 循环都会通过请求预算感知此次取消，随后在下方解除已绑定的会话。
		go func() {
			var extra [1]byte
			_, _ = connection.Read(extra[:])
			cancelRequest()
		}()
		result, err := store.handleContext(requestContext, validated)
		if requestContext.Err() != nil {
			sessionID := validated.Workflow.SessionID
			if sessionID == "" {
				sessionID = result.Diagnostics.SessionID
			}
			store.cancelSession(sessionID)
			return false
		}
		if err != nil {
			writeAcquisitionDaemonResponse(connection, daemonFailure("acquisition_failed", "acquisition request failed"))
			return false
		}
		if result.Protocol == "" {
			result.Protocol = protocolName
		}
		if result.RequestID == "" {
			result.RequestID = validated.RequestID
		}
		writeAcquisitionDaemonResponse(connection, acquisitionDaemonResponse{
			SchemaVersion: acquisitionDaemonSchemaVersion, Result: &result,
		})
	default:
		writeAcquisitionDaemonResponse(connection, daemonFailure("invalid_command", "daemon command is not supported"))
	}
	return false
}

func serveAcquisitionDaemon(endpointPath string) error {
	clientPath, _ := os.Executable()
	return serveAcquisitionDaemonAs(endpointPath, "", clientPath, true)
}

func serveAcquisitionDaemonForClient(endpointPath, clientPath string) error {
	return serveAcquisitionDaemonAs(endpointPath, "", clientPath, false)
}

func acquisitionDaemonHelperContext(advertisedProviderPath string) (bool, string) {
	if advertisedProviderPath == "" {
		return false, ""
	}
	return true, "used"
}

func validateAcquisitionDaemonProviderVersion(advertised string) error {
	if strings.TrimSpace(advertised) == "" || advertised != version {
		return errors.New("daemon helper version does not match the provider launcher")
	}
	return nil
}

func serveAcquisitionDaemonAs(endpointPath, advertisedProviderPath, clientPath string, developmentTCP bool) error {
	helperMode, helperStatus := acquisitionDaemonHelperContext(advertisedProviderPath)
	validatedHelperMode, validatedHelperStatus, identityErr := acquisitionDaemonRuntimeContext(advertisedProviderPath)
	if identityErr != nil {
		return identityErr
	}
	if validatedHelperMode != helperMode || validatedHelperStatus != helperStatus {
		return errors.New("daemon runtime identity context does not match the requested role")
	}
	path, err := validateDaemonEndpointPath(endpointPath)
	if err != nil {
		return err
	}
	clientPath, err = validateAcquisitionClientPath(clientPath)
	if err != nil {
		return err
	}
	token, err := randomDaemonToken()
	if err != nil {
		return err
	}
	listener, transport, address, cleanupTransport, err := listenAcquisitionDaemon(path, token, developmentTCP)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer cleanupTransport()
	executable, _ := os.Executable()
	executable, _ = filepath.EvalSymlinks(executable)
	if advertisedProviderPath == "" {
		advertisedProviderPath = executable
	}
	endpoint := acquisitionDaemonEndpoint{
		SchemaVersion: acquisitionDaemonSchemaVersion, Address: address, Transport: transport, Token: token,
		PID: os.Getpid(), Version: version, ProviderPath: advertisedProviderPath, DaemonPath: executable,
		ClientPath: clientPath, StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeDaemonEndpoint(path, endpoint); err != nil {
		return err
	}
	defer removeDaemonEndpoint(path, token)
	store := newAcquisitionSessionStore()
	if helperMode {
		// serve-helper is the installed companion process. Carry that machine
		// context into acquisition before diagnostics are finalized; do not patch
		// a finalized response afterward.
		store.helperMode = true
		store.helperStatus = helperStatus
	}
	var handlers sync.WaitGroup
	var activeHandlers atomic.Int64
	// 等待连接处理程序退出前先取消会话，使已感知取消的扫描能在关闭期间正常结束。
	defer handlers.Wait()
	defer store.closeAll()
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { _ = listener.Close() }) }
	idleSince := time.Now()
	for {
		setAcquisitionDaemonListenerDeadline(listener, time.Now().Add(time.Second))
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			if timeout, ok := acceptErr.(net.Error); ok && timeout.Timeout() {
				if store.activeCount() > 0 || activeHandlers.Load() > 0 {
					idleSince = time.Now()
					continue
				}
				if time.Since(idleSince) >= acquisitionDaemonIdleLifetime {
					return nil
				}
				continue
			}
			return acceptErr
		}
		idleSince = time.Now()
		handlers.Add(1)
		activeHandlers.Add(1)
		go func() {
			defer handlers.Done()
			defer activeHandlers.Add(-1)
			if handleAcquisitionDaemonConnection(connection, endpoint, store) {
				stop()
			}
		}()
	}
}
