// Package command 持有与平台无关的命令工作流。进程加固、调用方信任、daemon transport
// 和 OS helper 分派仍位于 composition root。
package command

import (
	"errors"
	"runtime"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

type Runtime struct {
	OptionPolicy       acquisitionmodel.OptionPolicy
	Acquisition        acquisitionmodel.WorkflowRuntime
	ClearSensitive     func([]byte)
	PlatformName       func() string
	SecurityPosture    func() string
	DiagnosticDefaults func() diagnosticmodel.PlatformDefaults
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func (value Runtime) normalized() Runtime {
	if value.ClearSensitive == nil {
		value.ClearSensitive = clearBytes
	}
	if value.OptionPolicy.ClearSensitive == nil {
		value.OptionPolicy.ClearSensitive = value.ClearSensitive
	}
	if value.Acquisition.ClearSensitive == nil {
		value.Acquisition.ClearSensitive = value.ClearSensitive
	}
	if value.PlatformName == nil {
		value.PlatformName = func() string { return "" }
	}
	if value.SecurityPosture == nil {
		value.SecurityPosture = func() string { return "" }
	}
	if value.DiagnosticDefaults == nil {
		value.DiagnosticDefaults = func() diagnosticmodel.PlatformDefaults { return diagnosticmodel.PlatformDefaults{} }
	}
	return value
}

func ExecuteOneShot(
	request protocolmodel.AcquireRequest,
	helperMode bool,
	helperStatus string,
	runtime Runtime,
) (protocolmodel.Response, error) {
	if request.Workflow.Operation != "finalize" || request.Workflow.SessionID != "" {
		return protocolmodel.Response{}, errors.New("prepare/observe/cancel 或已有 session 的 finalize 必须通过 daemon 入口")
	}
	runtime = runtime.normalized()
	options, err := acquisitionmodel.ParseOptions(request, runtime.OptionPolicy)
	if err != nil {
		return protocolmodel.Response{}, err
	}
	options.HelperMode = helperMode
	options.HelperStatus = helperStatus
	result, err := acquisitionmodel.Run(options, runtime.Acquisition)
	if err != nil {
		return protocolmodel.Response{}, err
	}
	result.Protocol = request.Protocol
	result.RequestID = request.RequestID
	return protocolmodel.EnforceSecretPolicy(result), nil
}

func SecurityPostureResponse(
	request protocolmodel.AcquireRequest,
	options acquisitionmodel.Options,
	platform string,
	posture string,
	defaults diagnosticmodel.PlatformDefaults,
) protocolmodel.Response {
	diag := diagnosticmodel.NewWithPlatformDefaults(
		platform, diagnosticmodel.RequestedScopes(options.Database, options.Media), defaults,
	)
	diag.SecurityPostureStatus = posture
	diag.ActionStage = "security_posture_revalidation"
	diagnosticmodel.ApplyOutcome(&diag, diagnosticmodel.FixedOutcome(
		diagnosticmodel.DecisionContext{Diagnostics: diag},
		"unsupported", "blocked", "stop_and_report", "security_posture_not_verified",
	))
	if platform == "darwin" {
		switch posture {
		case "sip_enabled_verified":
			diagnosticmodel.ApplyOutcome(&diag, diagnosticmodel.FixedOutcome(
				diagnosticmodel.DecisionContext{Diagnostics: diag}, "complete", "terminal", "none",
			))
		case "sip_disabled_verified":
			diag.SecurityPostureStatus = "restoration_required"
			diagnosticmodel.ApplyOutcome(&diag, diagnosticmodel.FixedOutcome(
				diagnosticmodel.DecisionContext{Diagnostics: diag}, "action_required", "waiting_action", "reenable_sip",
			))
		}
	}
	diagnosticmodel.ApplyPlatformDefaults(&diag, defaults)
	return protocolmodel.Response{Protocol: request.Protocol, RequestID: request.RequestID, Diagnostics: diag}
}

func ExecuteSecurityPostureRevalidation(request protocolmodel.AcquireRequest, runtime Runtime) (protocolmodel.Response, error) {
	runtime = runtime.normalized()
	options, err := acquisitionmodel.ParseSecurityPostureOptions(request, runtime.OptionPolicy)
	if err != nil {
		return protocolmodel.Response{}, err
	}
	defer runtime.ClearSensitive(options.CatalogKey)
	return SecurityPostureResponse(
		request, options, runtime.PlatformName(), runtime.SecurityPosture(), runtime.DiagnosticDefaults(),
	), nil
}
