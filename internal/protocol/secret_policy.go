package protocol

import diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"

// WithoutSecrets 保留相同的响应元数据和 diagnostics，同时移除全部携带凭据的字段。
func WithoutSecrets(value Response) Response {
	value.DatabaseKeys = nil
	value.DatabaseProfiles = nil
	value.DatabaseCredential = nil
	value.ImageKeys = nil
	return value
}

func HasCompleteRequestedCoverage(diag diagnosticmodel.Diagnostics) bool {
	if len(diag.RequestedScopes) == 0 {
		return false
	}
	for _, scope := range diag.RequestedScopes {
		switch scope {
		case "database":
			if diag.DatabaseCoverageStatus != "complete" {
				return false
			}
		case "media":
			if diag.MediaCoverageStatus != "complete" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// DiagnosticsPermitSecrets 是 one-shot 与 session 响应共享的唯一凭据发布策略。
func DiagnosticsPermitSecrets(diag diagnosticmodel.Diagnostics) bool {
	// Shadow uses a stricter inner result contract: no outer workflow status may
	// release credentials until the independently validated cleanup receipt says
	// every one-shot resource is absent. This check deliberately precedes the
	// legacy terminal-result policy below.
	if diag.ShadowAttempt != nil {
		attempt := diag.ShadowAttempt
		if err := attempt.Validate(); err != nil {
			return false
		}
		return attempt.Status == "ready" && attempt.CredentialReleased &&
			attempt.Receipt != nil && attempt.Receipt.Cleanup.Complete()
	}
	if diag.TargetBindingStatus == "mismatch" || diag.SessionAccountStatus == "known_other" {
		return false
	}
	for _, reason := range diag.BlockingReasons {
		switch reason {
		case "account_mismatch", "catalog_drift", "helper_untrusted", "security_posture_not_verified",
			"action_receipt_rejected", "duplicate_action_without_state_change", "acquisition_request_in_progress":
			return false
		}
	}
	if diag.WorkflowStatus == "terminal" {
		switch diag.ResultCode {
		case "complete", "partial", "deadline_exhausted":
			return true
		}
	}
	return diag.ResultCode == "action_required" && diag.WorkflowStatus == "waiting_action" &&
		diag.NextAction == "reenable_sip" && diag.SecurityPostureStatus == "restoration_required" &&
		HasCompleteRequestedCoverage(diag)
}

func EnforceSecretPolicy(value Response) Response {
	if DiagnosticsPermitSecrets(value.Diagnostics) {
		return value
	}
	return WithoutSecrets(value)
}
