package daemon

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
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

const (
	SchemaVersion = 2
	idleLifetime  = 20 * time.Second
	authTimeout   = 5 * time.Second
)

// Endpoint is the private connection descriptor published for a daemon client.
type Endpoint struct {
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

// Request is one authenticated daemon command frame.
type Request struct {
	SchemaVersion int                           `json:"schema_version"`
	Token         string                        `json:"token"`
	Command       string                        `json:"command"`
	Acquire       *protocolmodel.AcquireRequest `json:"acquire,omitempty"`
}

// Error is the stable daemon transport error envelope.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response is one daemon command response frame.
type Response struct {
	SchemaVersion int                     `json:"schema_version"`
	Status        string                  `json:"status,omitempty"`
	Result        *protocolmodel.Response `json:"result,omitempty"`
	Error         *Error                  `json:"error,omitempty"`
}

// BackendContext carries the runtime role established before a session store
// is created. It prevents the transport package from reaching into Provider
// session internals.
type BackendContext struct {
	HelperMode   bool
	HelperStatus string
}

// Backend is the narrow lifecycle surface the daemon needs from acquisition.
// Function fields keep the Provider's concrete session store private.
type Backend struct {
	HandleContext func(context.Context, protocolmodel.AcquireRequest) (protocolmodel.Response, error)
	CancelSession func(string)
	ActiveCount   func() int
	Close         func()
}

func (backend Backend) validate() error {
	if backend.HandleContext == nil || backend.CancelSession == nil || backend.ActiveCount == nil || backend.Close == nil {
		return errors.New("daemon acquisition backend is incomplete")
	}
	return nil
}

// Config defines the explicit trust and acquisition seams owned by the
// Provider composition root. Native transport and framing remain in this
// package; release identity policy remains with the Provider runtime.
type Config struct {
	Version            string
	ReleaseBuild       bool
	NewBackend         func(BackendContext) Backend
	RuntimeContext     func(string) (bool, string, error)
	ValidateClientPath func(string) (string, error)
	IsLinkOrReparse    func(string, fs.FileMode) (bool, error)
	SamePath           func(string, string) bool
	MarkSensitive      func([]byte)
	ZeroSensitive      func([]byte)
}

// Service owns daemon framing, transport and lifecycle while delegating only
// Provider-specific trust decisions and acquisition work through Config.
type Service struct {
	config Config
}

// New validates the package boundary once so serving cannot start with a
// partially wired security policy.
func New(config Config) (*Service, error) {
	if strings.TrimSpace(config.Version) == "" || config.NewBackend == nil || config.RuntimeContext == nil ||
		config.ValidateClientPath == nil || config.IsLinkOrReparse == nil ||
		config.SamePath == nil || config.MarkSensitive == nil || config.ZeroSensitive == nil {
		return nil, errors.New("daemon configuration is incomplete")
	}
	return &Service{config: config}, nil
}

// ContextForProvider derives the requested acquisition role from whether a
// companion helper advertises its original Provider launcher.
func ContextForProvider(advertisedProviderPath string) BackendContext {
	if advertisedProviderPath == "" {
		return BackendContext{}
	}
	return BackendContext{HelperMode: true, HelperStatus: "used"}
}

// ValidateProviderVersion enforces an exact Provider/helper version match.
func ValidateProviderVersion(advertised, current string) error {
	if strings.TrimSpace(advertised) == "" || advertised != current {
		return errors.New("daemon helper version does not match the provider launcher")
	}
	return nil
}

// RandomToken creates the short-lived authentication token shared by daemon
// and helper transports while guaranteeing that the raw random bytes are wiped.
func RandomToken(zeroSensitive func([]byte)) (string, error) {
	if zeroSensitive == nil {
		return "", errors.New("daemon token cleanup is unavailable")
	}
	raw := make([]byte, 32)
	defer zeroSensitive(raw)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (service *Service) validateEndpointPath(path string) (string, error) {
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
		unsafeParent, err = service.config.IsLinkOrReparse(parent, info.Mode())
	}
	if err != nil || !info.IsDir() || unsafeParent {
		return "", errors.New("daemon endpoint parent is not a trusted directory")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || !service.config.SamePath(parent, resolved) {
		return "", errors.New("daemon endpoint parent contains a link")
	}
	if err := validateDirectorySecurity(parent); err != nil {
		return "", err
	}
	if existing, statErr := os.Lstat(absolute); statErr == nil {
		unsafeEndpoint, safetyErr := service.config.IsLinkOrReparse(absolute, existing.Mode())
		if safetyErr != nil || unsafeEndpoint || !existing.Mode().IsRegular() {
			return "", errors.New("daemon endpoint cannot be a link or reparse point")
		}
	} else if !os.IsNotExist(statErr) {
		return "", errors.New("daemon endpoint cannot be inspected")
	}
	return absolute, nil
}

func (service *Service) writeEndpoint(path string, endpoint Endpoint) error {
	payload, err := json.MarshalIndent(endpoint, "", "  ")
	if err != nil {
		return err
	}
	service.config.MarkSensitive(payload)
	defer service.config.ZeroSensitive(payload)
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

func (service *Service) removeEndpoint(path, token string) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return
	}
	service.config.MarkSensitive(payload)
	defer service.config.ZeroSensitive(payload)
	var current Endpoint
	if json.Unmarshal(payload, &current) == nil && subtle.ConstantTimeCompare([]byte(current.Token), []byte(token)) == 1 {
		_ = os.Remove(path)
	}
}

func failure(code, message string) Response {
	return Response{
		SchemaVersion: SchemaVersion,
		Error:         &Error{Code: code, Message: message},
	}
}

func (service *Service) writeResponse(connection net.Conn, result Response) {
	payload, err := json.Marshal(result)
	if err != nil || len(payload)+1 > protocolmodel.MaxResponseBytes {
		payload, _ = json.Marshal(failure("response_too_large", "daemon response exceeded the safety limit"))
	}
	service.config.MarkSensitive(payload)
	defer service.config.ZeroSensitive(payload)
	_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.Copy(connection, bytes.NewReader(payload))
	_, _ = io.WriteString(connection, "\n")
}

func (service *Service) handleConnection(connection net.Conn, endpoint Endpoint, backend Backend) bool {
	defer connection.Close()
	peerIdentity, peerErr := verifyPeer(service.config, connection, endpoint.Transport, endpoint.ClientPath)
	if peerErr != nil {
		service.writeResponse(connection, failure("unauthorized_peer", "daemon client identity verification failed"))
		return false
	}
	// Identity verification is a short frame-parsing stage. Acquisition timing
	// starts only after peer, token and request validation have completed.
	_ = connection.SetReadDeadline(time.Now().Add(authTimeout))
	reader := bufio.NewReaderSize(connection, protocolmodel.MaxRequestBytes+1)
	payload, err := reader.ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		service.writeResponse(connection, failure("invalid_request", "daemon request is empty or too large"))
		return false
	}
	if len(payload) == 0 || len(payload) > protocolmodel.MaxRequestBytes {
		service.writeResponse(connection, failure("invalid_request", "daemon request is empty or too large"))
		return false
	}
	service.config.MarkSensitive(payload)
	defer service.config.ZeroSensitive(payload)
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		service.writeResponse(connection, failure("invalid_request", "daemon request is invalid"))
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		service.writeResponse(connection, failure("invalid_request", "daemon request contains trailing data"))
		return false
	}
	if request.SchemaVersion != SchemaVersion || len(request.Token) != 64 ||
		subtle.ConstantTimeCompare([]byte(request.Token), []byte(endpoint.Token)) != 1 {
		service.writeResponse(connection, failure("unauthorized", "daemon authentication failed"))
		return false
	}
	switch request.Command {
	case "ping":
		service.writeResponse(connection, Response{SchemaVersion: SchemaVersion, Status: "ready"})
	case "shutdown":
		service.writeResponse(connection, Response{SchemaVersion: SchemaVersion, Status: "stopping"})
		return true
	case "acquire":
		if request.Acquire == nil {
			service.writeResponse(connection, failure("invalid_request", "acquire request is missing"))
			return false
		}
		encoded, err := json.Marshal(request.Acquire)
		if err != nil {
			service.writeResponse(connection, failure("invalid_request", "acquire request cannot be encoded"))
			return false
		}
		service.config.MarkSensitive(encoded)
		defer service.config.ZeroSensitive(encoded)
		validated, err := protocolmodel.DecodeRequestData(encoded)
		if err != nil {
			service.writeResponse(connection, failure("invalid_request", "acquire request failed validation"))
			return false
		}
		validated.PeerIdentity = peerIdentity
		_ = connection.SetReadDeadline(time.Time{})
		requestContext, cancelRequest := context.WithCancel(context.Background())
		defer cancelRequest()
		// Each connection accepts one request. EOF after the authenticated frame
		// means the CLI exited, so acquisition is cancelled and its session unbound.
		go func() {
			var extra [1]byte
			_, _ = connection.Read(extra[:])
			cancelRequest()
		}()
		result, err := backend.HandleContext(requestContext, validated)
		if requestContext.Err() != nil {
			sessionID := validated.Workflow.SessionID
			if sessionID == "" {
				sessionID = result.Diagnostics.SessionID
			}
			backend.CancelSession(sessionID)
			return false
		}
		if err != nil {
			service.writeResponse(connection, failure("acquisition_failed", "acquisition request failed"))
			return false
		}
		if result.Protocol == "" {
			result.Protocol = protocolmodel.Name
		}
		if result.RequestID == "" {
			result.RequestID = validated.RequestID
		}
		service.writeResponse(connection, Response{SchemaVersion: SchemaVersion, Result: &result})
	default:
		service.writeResponse(connection, failure("invalid_command", "daemon command is not supported"))
	}
	return false
}

// Serve starts the development transport using the current executable as the
// expected client image.
func (service *Service) Serve(endpointPath string) error {
	clientPath, _ := os.Executable()
	return service.ServeAs(endpointPath, "", clientPath, true)
}

// ServeForClient starts the native transport bound to an explicit client.
func (service *Service) ServeForClient(endpointPath, clientPath string) error {
	return service.ServeAs(endpointPath, "", clientPath, false)
}

// ServeAs starts a daemon in Provider or companion-helper mode.
func (service *Service) ServeAs(endpointPath, advertisedProviderPath, clientPath string, developmentTCP bool) error {
	requestedContext := ContextForProvider(advertisedProviderPath)
	validatedHelperMode, validatedHelperStatus, identityErr := service.config.RuntimeContext(advertisedProviderPath)
	if identityErr != nil {
		return identityErr
	}
	if validatedHelperMode != requestedContext.HelperMode || validatedHelperStatus != requestedContext.HelperStatus {
		return errors.New("daemon runtime identity context does not match the requested role")
	}
	path, err := service.validateEndpointPath(endpointPath)
	if err != nil {
		return err
	}
	clientPath, err = service.config.ValidateClientPath(clientPath)
	if err != nil {
		return err
	}
	backend := service.config.NewBackend(requestedContext)
	if err := backend.validate(); err != nil {
		return err
	}
	token, err := RandomToken(service.config.ZeroSensitive)
	if err != nil {
		backend.Close()
		return err
	}
	listener, transport, address, cleanupTransport, err := listen(service.config, path, token, developmentTCP)
	if err != nil {
		backend.Close()
		return err
	}
	defer listener.Close()
	defer cleanupTransport()
	executable, _ := os.Executable()
	executable, _ = filepath.EvalSymlinks(executable)
	if advertisedProviderPath == "" {
		advertisedProviderPath = executable
	}
	endpoint := Endpoint{
		SchemaVersion: SchemaVersion, Address: address, Transport: transport, Token: token,
		PID: os.Getpid(), Version: service.config.Version, ProviderPath: advertisedProviderPath, DaemonPath: executable,
		ClientPath: clientPath, StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := service.writeEndpoint(path, endpoint); err != nil {
		backend.Close()
		return err
	}
	defer service.removeEndpoint(path, token)
	var handlers sync.WaitGroup
	var activeHandlers atomic.Int64
	// Cancel sessions before waiting for request handlers so budget-aware scans
	// can leave cleanly during shutdown.
	defer handlers.Wait()
	defer backend.Close()
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { _ = listener.Close() }) }
	idleSince := time.Now()
	for {
		setListenerDeadline(listener, time.Now().Add(time.Second))
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			if timeout, ok := acceptErr.(net.Error); ok && timeout.Timeout() {
				if backend.ActiveCount() > 0 || activeHandlers.Load() > 0 {
					idleSince = time.Now()
					continue
				}
				if time.Since(idleSince) >= idleLifetime {
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
			if service.handleConnection(connection, endpoint, backend) {
				stop()
			}
		}()
	}
}
