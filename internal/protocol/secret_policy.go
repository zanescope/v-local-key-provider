package protocol

import diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"

// WithoutSecrets returns the same response metadata and diagnostics while
// removing every credential-bearing field.
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

// DiagnosticsPermitSecrets is the single publication decision shared by
// one-shot and session responses.
func DiagnosticsPermitSecrets(diag diagnosticmodel.Diagnostics) bool {
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
