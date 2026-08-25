package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	commandmodel "github.com/zanescope/v-local-key-provider/internal/command"
)

var version = "0.1.0-dev.0"

// BuildConfig carries linker-stamped command metadata across the narrow cmd
// wiring boundary. Runtime behavior remains owned and tested by this package.
type BuildConfig struct {
	Version                string
	Mode                   string
	ReleaseSignerSHA256    string
	ReleasePromotionSHA256 string
}

// Run executes the Provider command using metadata supplied by the tiny cmd
// package. Signed builders continue stamping main.* symbols in that command,
// so moving the wiring cannot silently drop release trust markers.
func Run(config BuildConfig) int {
	if config.Version != "" {
		version = config.Version
	}
	buildMode = config.Mode
	releaseSignerSHA256 = config.ReleaseSignerSHA256
	releasePromotionSHA256 = config.ReleasePromotionSHA256
	return runMain()
}

func writeError(err error, code int) int {
	fmt.Fprintf(os.Stderr, "v-local-key-provider: %v\n", err)
	return code
}

func writeProtocolResponse(result response) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	markSensitiveBytes(payload)
	defer zeroBytes(payload)
	if _, err = io.Copy(os.Stdout, bytes.NewReader(payload)); err != nil {
		return err
	}
	_, err = io.WriteString(os.Stdout, "\n")
	return err
}

func executeOneShotAcquire(request acquireRequest, helperMode bool, helperStatus string) (response, error) {
	return commandmodel.ExecuteOneShot(request, helperMode, helperStatus, commandWorkflowRuntime())
}

func commandWorkflowRuntime() commandmodel.Runtime {
	return commandmodel.Runtime{
		OptionPolicy:       acquisitionOptionPolicy(),
		Acquisition:        acquisitionWorkflowRuntime(),
		ClearSensitive:     zeroBytes,
		PlatformName:       platformNameForDiagnostics,
		SecurityPosture:    defaultSecurityPostureStatus,
		DiagnosticDefaults: platformDiagnosticDefaults,
	}
}

func securityPostureRevalidationResponse(request acquireRequest, options acquireOptions, platform, posture string) response {
	return commandmodel.SecurityPostureResponse(
		request, options, platform, posture, platformDiagnosticDefaults(),
	)
}

func executeSecurityPostureRevalidation(request acquireRequest) (response, error) {
	return commandmodel.ExecuteSecurityPostureRevalidation(request, commandWorkflowRuntime())
}

func runMain() int {
	if err := hardenSensitiveProcess(); err != nil {
		return writeError(errors.New("crash artifact protection could not be enabled"), 3)
	}
	if err := validateRuntimeComponent(runtimeRole()); err != nil {
		return writeError(errors.New("runtime component identity verification failed"), 3)
	}
	if len(os.Args) >= 2 && os.Args[1] == "internal-hook-watchdog" {
		if err := runPlatformHookWatchdog(os.Args[2:]); err != nil {
			return writeError(err, 3)
		}
		return 0
	}
	if len(os.Args) == 4 && os.Args[1] == "helper-acquire-loopback" {
		if err := runPlatformElevatedHelperClient(os.Args[2], os.Args[3]); err != nil {
			return writeError(err, 3)
		}
		return 0
	}
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Fprintln(os.Stdout, version)
		return 0
	}
	if len(os.Args) == 2 && os.Args[1] == "daemon" {
		if err := runAcquisitionDaemon(os.Stdin, os.Stdout); err != nil {
			return writeError(err, 3)
		}
		return 0
	}
	if len(os.Args) == 5 && os.Args[1] == "daemon" && os.Args[2] == "serve" {
		if handled, err := delegateAcquisitionDaemonToPlatformHelper(os.Args[3], os.Args[4]); handled {
			if err != nil {
				return writeError(err, 3)
			}
			return 0
		}
		if err := serveAcquisitionDaemonForClient(os.Args[3], os.Args[4]); err != nil {
			return writeError(err, 3)
		}
		return 0
	}
	if len(os.Args) == 7 && os.Args[1] == "daemon" && os.Args[2] == "serve-helper" {
		if err := validateAcquisitionDaemonProviderVersion(os.Args[6]); err != nil {
			return writeError(err, 3)
		}
		if err := serveAcquisitionDaemonAs(os.Args[3], os.Args[4], os.Args[5], false); err != nil {
			return writeError(err, 3)
		}
		return 0
	}
	if len(os.Args) != 2 || (os.Args[1] != "acquire" && os.Args[1] != "helper-acquire") {
		return writeError(errors.New("用法：v-local-key-provider acquire < request.json；或 v-local-key-provider daemon"), 2)
	}
	helperMode := os.Args[1] == "helper-acquire"
	if err := validateOneShotCaller(helperMode); err != nil {
		return writeError(errors.New("one-shot caller identity verification failed"), 3)
	}
	payload, err := readRequest(os.Stdin)
	if err != nil {
		return writeError(err, 2)
	}
	markSensitiveBytes(payload)
	defer zeroBytes(payload)
	request, err := decodeRequestData(payload)
	if err != nil {
		return writeError(err, 2)
	}
	if request.Workflow.Operation == "revalidate_security_posture" {
		result, executeErr := executeSecurityPostureRevalidation(request)
		if executeErr != nil {
			return writeError(executeErr, 3)
		}
		if err := writeProtocolResponse(result); err != nil {
			return writeError(errors.New("编码协议响应失败"), 4)
		}
		return 0
	}
	if request.Workflow.Operation != "finalize" || request.Workflow.SessionID != "" {
		return writeError(errors.New("prepare/observe/cancel 或已有 session 的 finalize 必须通过 daemon 入口"), 2)
	}
	helperStatus := ""
	options, err := optionsFromRequest(request)
	if err != nil {
		return writeError(err, 2)
	}
	if !helperMode {
		delegated, status := delegateToPlatformHelper(payload, budget{value: options.Budget})
		if delegated {
			return 0
		}
		helperStatus = status
	}
	zeroBytes(options.CatalogKey)
	result, err := executeOneShotAcquire(request, helperMode, helperStatus)
	if err != nil {
		return writeError(err, 3)
	}
	result.Protocol = request.Protocol
	result.RequestID = request.RequestID
	if err := writeProtocolResponse(result); err != nil {
		return writeError(errors.New("编码协议响应失败"), 4)
	}
	return 0
}
