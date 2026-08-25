package provider

import "time"

func waitingSessionResponse(request acquireRequest, session *acquisitionSession) response {
	if session.Latest != nil {
		result := responseWithoutSecrets(*session.Latest)
		result.RequestID = request.RequestID
		result.Diagnostics.SessionID = session.ID
		result.Diagnostics.ProcessInstanceID = session.ProcessInstanceID
		return result
	}
	return blockedSessionResponse(request, session, "action_receipt_required")
}

func cancelledSessionResponse(request acquireRequest, session *acquisitionSession, processInstanceID string) response {
	databaseCoverageStatus, mediaCoverageStatus := terminalEmptyCoverageStatuses(session.Scopes)
	diag := newDiagnostics(platformNameForDiagnostics(), session.Scopes)
	applyFixedDiagnosticOutcome(&diag, "cancelled", "terminal", "none", "user_cancelled")
	diag.DatabaseTargetStatus = databaseTargetStatus(session.Scopes, session.Latest)
	diag.DatabaseCoverageStatus = databaseCoverageStatus
	diag.MediaCoverageStatus = mediaCoverageStatus
	diag.SessionID = session.ID
	diag.ProcessInstanceID = processInstanceID
	diag.ActionStage = "cancel"
	return response{Protocol: protocolName, RequestID: request.RequestID, CatalogID: session.CatalogID, Diagnostics: diag}
}

func blockedSessionResponse(request acquireRequest, session *acquisitionSession, reason string) response {
	if session.Latest != nil {
		result := responseWithoutSecrets(*session.Latest)
		result.RequestID = request.RequestID
		applyFixedDiagnosticOutcome(&result.Diagnostics, "action_required", "blocked", "stop_and_report", reason)
		result.Diagnostics.SessionID = session.ID
		result.Diagnostics.SessionExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339Nano)
		result.Diagnostics.ProcessInstanceID = session.ProcessInstanceID
		result.Diagnostics.ActionStage = session.LastActionStage
		return result
	}
	databaseCoverageStatus, mediaCoverageStatus := terminalEmptyCoverageStatuses(session.Scopes)
	diag := newDiagnostics(platformNameForDiagnostics(), session.Scopes)
	applyFixedDiagnosticOutcome(&diag, "action_required", "blocked", "stop_and_report", reason)
	diag.DatabaseTargetStatus = databaseTargetStatus(session.Scopes, session.Latest)
	diag.DatabaseCoverageStatus = databaseCoverageStatus
	diag.MediaCoverageStatus = mediaCoverageStatus
	diag.SessionID = session.ID
	diag.SessionExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339Nano)
	diag.ProcessInstanceID = session.ProcessInstanceID
	diag.ActionStage = session.LastActionStage
	return response{Protocol: protocolName, RequestID: request.RequestID, CatalogID: session.CatalogID, Diagnostics: diag}
}
