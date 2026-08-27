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
	SchemaVersion = 1
	idleLifetime  = 20 * time.Second
	authTimeout   = 5 * time.Second
)

// Endpoint 是向 daemon client 发布的私有连接描述符。
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

// Request 是一个经过认证的 daemon 命令 frame。
type Request struct {
	SchemaVersion int                           `json:"schema_version"`
	Token         string                        `json:"token"`
	Command       string                        `json:"command"`
	Acquire       *protocolmodel.AcquireRequest `json:"acquire,omitempty"`
}

// Error 是稳定的 daemon transport 错误 envelope。
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response 是一个 daemon 命令响应 frame。
type Response struct {
	SchemaVersion int                     `json:"schema_version"`
	Status        string                  `json:"status,omitempty"`
	Result        *protocolmodel.Response `json:"result,omitempty"`
	Error         *Error                  `json:"error,omitempty"`
}

// BackendContext 携带在创建 session store 前确定的运行时角色，防止 transport package
// 访问 Provider session 内部实现。
type BackendContext struct {
	HelperMode   bool
	HelperStatus string
}

// Backend 是 daemon 从 acquisition 所需的窄生命周期接口。函数字段使 Provider 的具体
// session store 保持私有。
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

// Config 定义 Provider composition root 持有的显式信任和采集边界。原生 transport 与
// framing 留在本 package；release 身份策略仍归 Provider runtime 所有。
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

// Service 持有 daemon framing、transport 和生命周期，只通过 Config 委托 Provider 特有的
// 信任决策与采集工作。
type Service struct {
	config Config
}

// New 一次性验证 package 边界，避免在安全策略只完成部分装配时启动服务。
func New(config Config) (*Service, error) {
	if strings.TrimSpace(config.Version) == "" || config.NewBackend == nil || config.RuntimeContext == nil ||
		config.ValidateClientPath == nil || config.IsLinkOrReparse == nil ||
		config.SamePath == nil || config.MarkSensitive == nil || config.ZeroSensitive == nil {
		return nil, errors.New("daemon configuration is incomplete")
	}
	return &Service{config: config}, nil
}

// ContextForProvider 根据 companion helper 是否声明原始 Provider launcher，推导请求的
// 采集角色。
func ContextForProvider(advertisedProviderPath string) BackendContext {
	if advertisedProviderPath == "" {
		return BackendContext{}
	}
	return BackendContext{HelperMode: true, HelperStatus: "used"}
}

// ValidateProviderVersion 强制 Provider 与 helper 版本精确匹配。
func ValidateProviderVersion(advertised, current string) error {
	if strings.TrimSpace(advertised) == "" || advertised != current {
		return errors.New("daemon helper version does not match the provider launcher")
	}
	return nil
}

// RandomToken 创建由 daemon 和 helper transport 共享的短生命周期认证 token，并保证
// 原始随机字节会被擦除。
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
	// 身份验证只是短暂的 frame 解析阶段。只有完成 peer、token 和请求验证后，才开始计算
	// 采集时间。
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
		// 每个连接只接受一个请求。已认证 frame 后出现 EOF 表示 CLI 已退出，因此取消采集并
		// 解除其 session 绑定。
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

// Serve 启动 development transport，并把当前可执行文件作为预期 client image。
func (service *Service) Serve(endpointPath string) error {
	clientPath, _ := os.Executable()
	return service.ServeAs(endpointPath, "", clientPath, true)
}

// ServeForClient 启动绑定到指定 client 的原生 transport。
func (service *Service) ServeForClient(endpointPath, clientPath string) error {
	return service.ServeAs(endpointPath, "", clientPath, false)
}

// ServeAs 以 Provider 或 companion-helper 模式启动 daemon。
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
	// 在等待请求 handler 前先取消 session，使感知 budget 的扫描能在 shutdown 时干净退出。
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
