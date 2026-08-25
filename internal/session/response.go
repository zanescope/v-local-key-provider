package session

import (
	"time"

	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

func (coordinator *Coordinator) waitingResponse(request protocolmodel.AcquireRequest, record *Record) protocolmodel.Response {
	if record.Latest != nil {
		result := protocolmodel.WithoutSecrets(*record.Latest)
		result.RequestID = request.RequestID
		result.Diagnostics.SessionID = record.ID
		result.Diagnostics.ProcessInstanceID = record.ProcessInstanceID
		return result
	}
	return coordinator.blockedResponse(request, record, "action_receipt_required")
}

func (coordinator *Coordinator) cancelledResponse(request protocolmodel.AcquireRequest, record *Record, processInstanceID string) protocolmodel.Response {
	databaseCoverageStatus, mediaCoverageStatus := TerminalEmptyCoverageStatuses(record.Scopes)
	diag := coordinator.runtime.NewDiagnostics(record.Scopes)
	applyFixedOutcome(&diag, "cancelled", "terminal", "none", "user_cancelled")
	diag.DatabaseTargetStatus = DatabaseTargetStatus(record.Scopes, record.Latest)
	diag.DatabaseCoverageStatus = databaseCoverageStatus
	diag.MediaCoverageStatus = mediaCoverageStatus
	diag.SessionID = record.ID
	diag.ProcessInstanceID = processInstanceID
	diag.ActionStage = "cancel"
	return protocolmodel.Response{
		Protocol: coordinator.runtime.Protocol, RequestID: request.RequestID,
		CatalogID: record.CatalogID, Diagnostics: diag,
	}
}

func (coordinator *Coordinator) blockedResponse(request protocolmodel.AcquireRequest, record *Record, reason string) protocolmodel.Response {
	if record.Latest != nil {
		result := protocolmodel.WithoutSecrets(*record.Latest)
		result.RequestID = request.RequestID
		applyFixedOutcome(&result.Diagnostics, "action_required", "blocked", "stop_and_report", reason)
		result.Diagnostics.SessionID = record.ID
		result.Diagnostics.SessionExpiresAt = record.ExpiresAt.UTC().Format(time.RFC3339Nano)
		result.Diagnostics.ProcessInstanceID = record.ProcessInstanceID
		result.Diagnostics.ActionStage = record.LastActionStage
		return result
	}
	databaseCoverageStatus, mediaCoverageStatus := TerminalEmptyCoverageStatuses(record.Scopes)
	diag := coordinator.runtime.NewDiagnostics(record.Scopes)
	applyFixedOutcome(&diag, "action_required", "blocked", "stop_and_report", reason)
	diag.DatabaseTargetStatus = DatabaseTargetStatus(record.Scopes, record.Latest)
	diag.DatabaseCoverageStatus = databaseCoverageStatus
	diag.MediaCoverageStatus = mediaCoverageStatus
	diag.SessionID = record.ID
	diag.SessionExpiresAt = record.ExpiresAt.UTC().Format(time.RFC3339Nano)
	diag.ProcessInstanceID = record.ProcessInstanceID
	diag.ActionStage = record.LastActionStage
	return protocolmodel.Response{
		Protocol: coordinator.runtime.Protocol, RequestID: request.RequestID,
		CatalogID: record.CatalogID, Diagnostics: diag,
	}
}
