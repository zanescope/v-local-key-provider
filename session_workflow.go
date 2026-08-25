package provider

import (
	"context"
	"errors"
	"time"

	sessionmodel "github.com/zanescope/v-local-key-provider/internal/session"
)

func (store *acquisitionSessionStore) sessionRequest(ctx context.Context, request acquireRequest) (response, error) {
	processInstanceID := platformProcessInstanceID()
	begin, err := store.core.Begin(sessionmodel.BeginInput{
		SessionID: request.Workflow.SessionID, AccountDir: request.AccountDir, DBDir: request.DBDir,
		Scopes: request.Scopes, ClientIdentity: request.PeerIdentity, Operation: request.Workflow.Operation,
		ExpectedCatalogID: request.Workflow.ExpectedCatalogID, ActionReceipt: request.Workflow.ActionReceipt,
		CurrentProcessInstanceID: processInstanceID,
	})
	if err != nil {
		return response{}, err
	}
	session := begin.Session
	if session == nil {
		return response{}, errors.New("acquisition session 状态快照缺失")
	}
	defer store.core.ReleaseSnapshot(session)
	switch begin.Status {
	case sessionmodel.BeginCancelled:
		return enforceResponseSecretPolicy(cancelledSessionResponse(request, session, processInstanceID)), nil
	case sessionmodel.BeginCatalogDrift:
		return enforceResponseSecretPolicy(blockedSessionResponse(request, session, "catalog_drift")), nil
	case sessionmodel.BeginInFlight:
		return enforceResponseSecretPolicy(blockedSessionResponse(request, session, "acquisition_request_in_progress")), nil
	case sessionmodel.BeginWaitingReceipt:
		return enforceResponseSecretPolicy(waitingSessionResponse(request, session)), nil
	case sessionmodel.BeginReceiptRejected:
		return enforceResponseSecretPolicy(blockedSessionResponse(request, session, "action_receipt_rejected")), nil
	case sessionmodel.BeginDuplicate:
		return enforceResponseSecretPolicy(blockedSessionResponse(request, session, "duplicate_action_without_state_change")), nil
	case sessionmodel.BeginRetryExhausted:
		return enforceResponseSecretPolicy(blockedSessionResponse(request, session, "action_retry_budget_exhausted")), nil
	case sessionmodel.BeginReady:
		// Continue below with the detached, deep-cloned state snapshot.
	default:
		return response{}, errors.New("acquisition session 状态转换无效")
	}
	defer store.core.FinishRequest(session.ID)

	options, err := optionsFromRequest(request)
	if err != nil {
		return response{}, err
	}
	zeroBytes(options.catalogKey)
	options.catalogKey = session.CatalogKey
	session.CatalogKey = nil
	defer zeroBytes(options.catalogKey)
	if platformSession, ok := session.PlatformSession.(acquisitionPlatformSession); ok {
		options.platformSession = platformSession
	}
	options.helperMode = store.helperMode
	options.helperStatus = store.helperStatus
	options.budget = options.budget.cappedAt(session.ExpiresAt).withCancellation(ctx.Done())
	if session.Context != nil {
		options.budget = options.budget.withCancellation(session.Context.Done())
	}
	if request.Workflow.ActionReceipt != nil {
		options.actionReceipt = request.Workflow.ActionReceipt.Action
	}
	started := session.CreatedAt
	targets := databaseTargets{catalog: databaseCatalog{}}
	catalogRefreshStarted := time.Now()
	if options.database {
		targets, err = discoverDatabaseTargetsWithKey(options.dbDir, options.budget, options.catalogKey)
		if err != nil {
			return response{}, err
		}
		if targets.catalog.CatalogID != session.CatalogID {
			return blockedSessionResponse(request, session, "catalog_drift"), nil
		}
	}
	catalogRefreshElapsed := time.Since(catalogRefreshStarted).Milliseconds()
	if request.Workflow.Operation == "finalize" && session.Latest != nil &&
		(session.Latest.Diagnostics.WorkflowStatus == "terminal" || begin.FinishCurrentPartial) {
		result := *session.Latest
		result.Protocol = protocolName
		result.RequestID = request.RequestID
		result.CatalogID = targets.catalog.CatalogID
		result.CatalogEntries = append([]catalogDatabase(nil), targets.catalog.Databases...)
		result.Profiles = profileSummaries()
		result.Diagnostics.SessionID = session.ID
		result.Diagnostics.SessionExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339Nano)
		result.Diagnostics.ProcessInstanceID = processInstanceID
		result.Diagnostics.ActionStage = "finalize"
		if begin.FinishCurrentPartial {
			applyFixedDiagnosticOutcome(&result.Diagnostics, "partial", "terminal", "none", "user_declined_action")
		}
		if result.Diagnostics.PhaseTimingsMS == nil {
			result.Diagnostics.PhaseTimingsMS = map[string]int64{}
		}
		result.Diagnostics.PhaseTimingsMS["catalog_refresh"] = catalogRefreshElapsed
		result.Diagnostics.PhaseTimingsMS["total"] = time.Since(session.CreatedAt).Milliseconds()
		if !store.core.Delete(session.ID) {
			return cancelledSessionResponse(request, session, processInstanceID), nil
		}
		return enforceResponseSecretPolicy(result), nil
	}
	var media mediaEvidence
	if options.media && (session.Latest == nil || session.Latest.ImageKeys == nil) {
		media = discoverMediaEvidence(options.accountDir, options.budget)
	}
	result, err := runIncrementalSessionAcquire(options, targets, media, session.Latest, started)
	if err != nil {
		return response{}, err
	}
	result.Protocol = protocolName
	result.RequestID = request.RequestID
	result.Diagnostics.SessionID = session.ID
	result.Diagnostics.SessionExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339Nano)
	result.Diagnostics.ProcessInstanceID = processInstanceID
	if result.Diagnostics.PhaseTimingsMS == nil {
		result.Diagnostics.PhaseTimingsMS = map[string]int64{}
	}
	result.Diagnostics.PhaseTimingsMS["catalog_refresh"] = catalogRefreshElapsed
	result.Diagnostics.PhaseTimingsMS["total"] = time.Since(session.CreatedAt).Milliseconds()
	result.Diagnostics.ActionStage = result.Diagnostics.NextAction
	if result.Diagnostics.ActionStage == "none" || result.Diagnostics.ActionStage == "" {
		result.Diagnostics.ActionStage = request.Workflow.Operation
	}
	if !store.core.Commit(session.ID, sessionmodel.CommitInput{
		Latest: result, LatestCatalogID: result.CatalogID, ProcessInstanceID: processInstanceID,
		LastRoute: result.Diagnostics.RouteSelected, LastActionStage: result.Diagnostics.ActionStage,
		Delete: request.Workflow.Operation == "finalize",
	}) {
		return cancelledSessionResponse(request, session, processInstanceID), nil
	}
	if request.Workflow.Operation == "observe" {
		return responseWithoutSecrets(result), nil
	}
	return enforceResponseSecretPolicy(result), nil
}

func (store *acquisitionSessionStore) handleContext(ctx context.Context, request acquireRequest) (response, error) {
	switch request.Workflow.Operation {
	case "prepare":
		return store.prepare(request)
	case "observe", "finalize", "cancel":
		return store.sessionRequest(ctx, request)
	default:
		return response{}, errors.New("workflow.operation 不受支持")
	}
}

func (store *acquisitionSessionStore) handle(request acquireRequest) (response, error) {
	return store.handleContext(context.Background(), request)
}
