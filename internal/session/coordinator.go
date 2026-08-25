package session

import (
	"context"
	"errors"
	"strings"
	"time"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

func applyFixedOutcome(diag *diagnosticmodel.Diagnostics, resultCode, workflowStatus, nextAction string, reasons ...string) {
	diagnosticmodel.ApplyOutcome(diag, diagnosticmodel.FixedOutcome(
		diagnosticmodel.DecisionContext{Diagnostics: *diag},
		resultCode, workflowStatus, nextAction, reasons...,
	))
}

func (coordinator *Coordinator) prepare(request protocolmodel.AcquireRequest, environment Environment) (protocolmodel.Response, error) {
	if !coordinator.store.Accepting() {
		return protocolmodel.Response{}, ErrStoreClosing
	}
	if err := coordinator.runtime.validatePrepare(); err != nil {
		return protocolmodel.Response{}, err
	}
	prepareStarted := time.Now()
	options, err := coordinator.runtime.ParseOptions(request)
	if err != nil {
		coordinator.runtime.ClearSensitive(options.CatalogKey)
		return protocolmodel.Response{}, err
	}
	defer coordinator.runtime.ClearSensitive(options.CatalogKey)
	options.HelperMode = environment.HelperMode
	options.HelperStatus = environment.HelperStatus

	targets := acquisitionmodel.Targets{Catalog: catalogmodel.Catalog{}}
	discoveryStarted := time.Now()
	if options.Database {
		if coordinator.runtime.DiscoverTargets == nil {
			return protocolmodel.Response{}, errors.New("session runtime 缺少 target discovery")
		}
		targets, err = coordinator.runtime.DiscoverTargets(options.DBDir, options.Budget, options.CatalogKey)
		if err != nil {
			return protocolmodel.Response{}, err
		}
	}
	discoveryElapsed := time.Since(discoveryStarted).Milliseconds()
	id, err := coordinator.runtime.NewOpaqueID()
	if err != nil {
		return protocolmodel.Response{}, err
	}
	processInstanceID := coordinator.runtime.ProcessInstanceID()
	record := coordinator.store.NewRecord(RecordInput{
		ID: id, AccountDir: options.AccountDir, DBDir: options.DBDir,
		CatalogKey: options.CatalogKey, CatalogID: targets.Catalog.CatalogID,
		Scopes: request.Scopes, ProcessInstanceID: processInstanceID,
		LastActionStage: "prepare", ClientIdentity: request.PeerIdentity,
	})
	routeStarted := time.Now()
	record.PlatformSession = coordinator.runtime.PreparePlatformSession(targets, options)
	routeElapsed := time.Since(routeStarted).Milliseconds()
	if err := coordinator.store.Insert(record); err != nil {
		coordinator.store.Discard(record)
		return protocolmodel.Response{}, err
	}

	diag := coordinator.runtime.NewDiagnostics(diagnosticmodel.RequestedScopes(options.Database, options.Media))
	applyFixedOutcome(&diag, "partial", "running", "none")
	diag.MissingDatabaseCount = targets.Count
	diag.MissingDatabaseIDs = diagnosticmodel.MissingDatabaseIDs(targets.Catalog, nil)
	diag.DatabaseCount = len(targets.Catalog.Databases)
	diag.RequiredDatabaseCount = targets.Count
	diag.SessionID = id
	diag.ProcessInstanceID = processInstanceID
	diag.SessionExpiresAt = record.ExpiresAt.UTC().Format(time.RFC3339Nano)
	diag.ActionStage = "prepare"
	diag.PhaseTimingsMS = map[string]int64{
		"target_database_discovery": discoveryElapsed,
		"route_prepare":             routeElapsed,
		"prepare_total":             time.Since(prepareStarted).Milliseconds(),
		"total":                     time.Since(prepareStarted).Milliseconds(),
	}
	if options.Database {
		diag.DatabaseTargetStatus = "none"
		if len(targets.Catalog.Databases) > 0 {
			diag.DatabaseTargetStatus = "present"
		}
		diag.DatabaseCoverageStatus = "none"
	}
	for _, database := range targets.Catalog.Databases {
		switch database.Classification {
		case catalogmodel.ClassificationPlaintext:
			diag.PlaintextDatabaseCount++
		case catalogmodel.ClassificationUnreadable:
			diag.UnreadableDatabaseCount++
		case catalogmodel.ClassificationUnstable:
			diag.UnstableDatabaseCount++
		case catalogmodel.ClassificationTruncated:
			diag.TruncatedDatabaseCount++
		}
	}
	if options.Media {
		diag.MediaCoverageStatus = "pending"
	}
	if platformSession, ok := record.PlatformSession.(acquisitionmodel.PlatformSession); ok && platformSession != nil {
		hook := platformSession.Status()
		diag.HookTargetFound = hook.TargetFound
		diag.HookInstalled = hook.Installed
		diag.RouteSelected = hook.Route
		if hook.RouteHistory != "" {
			diag.RoutesAttempted = strings.Split(hook.RouteHistory, "\x00")
		} else if hook.Route != "" {
			diag.RoutesAttempted = []string{hook.Route}
		}
	}
	coordinator.runtime.ApplyDiagnosticDefaults(&diag)
	return protocolmodel.Response{
		Protocol: coordinator.runtime.Protocol, RequestID: request.RequestID,
		CatalogID:      targets.Catalog.CatalogID,
		CatalogEntries: append([]catalogmodel.Database(nil), targets.Catalog.Databases...),
		Profiles:       coordinator.runtime.ProfileSummaries(), Diagnostics: diag,
	}, nil
}

func (coordinator *Coordinator) sessionRequest(ctx context.Context, request protocolmodel.AcquireRequest, environment Environment) (protocolmodel.Response, error) {
	processInstanceID := coordinator.runtime.ProcessInstanceID()
	begin, err := coordinator.store.Begin(BeginInput{
		SessionID: request.Workflow.SessionID, AccountDir: request.AccountDir, DBDir: request.DBDir,
		Scopes: request.Scopes, ClientIdentity: request.PeerIdentity, Operation: request.Workflow.Operation,
		ExpectedCatalogID: request.Workflow.ExpectedCatalogID, ActionReceipt: request.Workflow.ActionReceipt,
		CurrentProcessInstanceID: processInstanceID,
	})
	if err != nil {
		return protocolmodel.Response{}, err
	}
	record := begin.Session
	if record == nil {
		return protocolmodel.Response{}, errors.New("acquisition session 状态快照缺失")
	}
	defer coordinator.store.ReleaseSnapshot(record)
	switch begin.Status {
	case BeginCancelled:
		return protocolmodel.EnforceSecretPolicy(coordinator.cancelledResponse(request, record, processInstanceID)), nil
	case BeginCatalogDrift:
		return protocolmodel.EnforceSecretPolicy(coordinator.blockedResponse(request, record, "catalog_drift")), nil
	case BeginInFlight:
		return protocolmodel.EnforceSecretPolicy(coordinator.blockedResponse(request, record, "acquisition_request_in_progress")), nil
	case BeginWaitingReceipt:
		return protocolmodel.EnforceSecretPolicy(coordinator.waitingResponse(request, record)), nil
	case BeginReceiptRejected:
		return protocolmodel.EnforceSecretPolicy(coordinator.blockedResponse(request, record, "action_receipt_rejected")), nil
	case BeginDuplicate:
		return protocolmodel.EnforceSecretPolicy(coordinator.blockedResponse(request, record, "duplicate_action_without_state_change")), nil
	case BeginRetryExhausted:
		return protocolmodel.EnforceSecretPolicy(coordinator.blockedResponse(request, record, "action_retry_budget_exhausted")), nil
	case BeginReady:
		// Continue with the detached, deep-cloned state snapshot.
	default:
		return protocolmodel.Response{}, errors.New("acquisition session 状态转换无效")
	}
	defer coordinator.store.FinishRequest(record.ID)

	if coordinator.runtime.ParseOptions == nil {
		return protocolmodel.Response{}, errors.New("session runtime 缺少 options parser")
	}
	options, err := coordinator.runtime.ParseOptions(request)
	if err != nil {
		coordinator.runtime.ClearSensitive(options.CatalogKey)
		return protocolmodel.Response{}, err
	}
	coordinator.runtime.ClearSensitive(options.CatalogKey)
	options.CatalogKey = record.CatalogKey
	record.CatalogKey = nil
	defer coordinator.runtime.ClearSensitive(options.CatalogKey)
	if platformSession, ok := record.PlatformSession.(acquisitionmodel.PlatformSession); ok {
		options.PlatformSession = platformSession
	}
	options.HelperMode = environment.HelperMode
	options.HelperStatus = environment.HelperStatus
	options.Budget = options.Budget.CappedAt(record.ExpiresAt)
	if ctx != nil {
		options.Budget = options.Budget.WithCancellation(ctx.Done())
	}
	if record.Context != nil {
		options.Budget = options.Budget.WithCancellation(record.Context.Done())
	}
	if request.Workflow.ActionReceipt != nil {
		options.ActionReceipt = request.Workflow.ActionReceipt.Action
	}

	started := record.CreatedAt
	targets := acquisitionmodel.Targets{Catalog: catalogmodel.Catalog{}}
	catalogRefreshStarted := time.Now()
	if options.Database {
		if coordinator.runtime.DiscoverTargets == nil {
			return protocolmodel.Response{}, errors.New("session runtime 缺少 target discovery")
		}
		targets, err = coordinator.runtime.DiscoverTargets(options.DBDir, options.Budget, options.CatalogKey)
		if err != nil {
			return protocolmodel.Response{}, err
		}
		if targets.Catalog.CatalogID != record.CatalogID {
			return coordinator.blockedResponse(request, record, "catalog_drift"), nil
		}
	}
	catalogRefreshElapsed := time.Since(catalogRefreshStarted).Milliseconds()
	if request.Workflow.Operation == "finalize" && record.Latest != nil &&
		(record.Latest.Diagnostics.WorkflowStatus == "terminal" || begin.FinishCurrentPartial) {
		result := *record.Latest
		result.Protocol = coordinator.runtime.Protocol
		result.RequestID = request.RequestID
		result.CatalogID = targets.Catalog.CatalogID
		result.CatalogEntries = append([]catalogmodel.Database(nil), targets.Catalog.Databases...)
		result.Profiles = coordinator.runtime.ProfileSummaries()
		result.Diagnostics.SessionID = record.ID
		result.Diagnostics.SessionExpiresAt = record.ExpiresAt.UTC().Format(time.RFC3339Nano)
		result.Diagnostics.ProcessInstanceID = processInstanceID
		result.Diagnostics.ActionStage = "finalize"
		if begin.FinishCurrentPartial {
			applyFixedOutcome(&result.Diagnostics, "partial", "terminal", "none", "user_declined_action")
		}
		if result.Diagnostics.PhaseTimingsMS == nil {
			result.Diagnostics.PhaseTimingsMS = map[string]int64{}
		}
		result.Diagnostics.PhaseTimingsMS["catalog_refresh"] = catalogRefreshElapsed
		result.Diagnostics.PhaseTimingsMS["total"] = time.Since(record.CreatedAt).Milliseconds()
		if !coordinator.store.Delete(record.ID) {
			return coordinator.cancelledResponse(request, record, processInstanceID), nil
		}
		return protocolmodel.EnforceSecretPolicy(result), nil
	}

	var media acquisitionmodel.MediaEvidence
	if options.Media && (record.Latest == nil || record.Latest.ImageKeys == nil) {
		media = coordinator.runtime.DiscoverMedia(options.AccountDir, options.Budget)
	}
	result, err := coordinator.runIncremental(options, targets, media, record.Latest, started)
	if err != nil {
		return protocolmodel.Response{}, err
	}
	result.Protocol = coordinator.runtime.Protocol
	result.RequestID = request.RequestID
	result.Diagnostics.SessionID = record.ID
	result.Diagnostics.SessionExpiresAt = record.ExpiresAt.UTC().Format(time.RFC3339Nano)
	result.Diagnostics.ProcessInstanceID = processInstanceID
	if result.Diagnostics.PhaseTimingsMS == nil {
		result.Diagnostics.PhaseTimingsMS = map[string]int64{}
	}
	result.Diagnostics.PhaseTimingsMS["catalog_refresh"] = catalogRefreshElapsed
	result.Diagnostics.PhaseTimingsMS["total"] = time.Since(record.CreatedAt).Milliseconds()
	result.Diagnostics.ActionStage = result.Diagnostics.NextAction
	if result.Diagnostics.ActionStage == "none" || result.Diagnostics.ActionStage == "" {
		result.Diagnostics.ActionStage = request.Workflow.Operation
	}
	if !coordinator.store.Commit(record.ID, CommitInput{
		Latest: result, LatestCatalogID: result.CatalogID, ProcessInstanceID: processInstanceID,
		LastRoute: result.Diagnostics.RouteSelected, LastActionStage: result.Diagnostics.ActionStage,
		Delete: request.Workflow.Operation == "finalize",
	}) {
		return coordinator.cancelledResponse(request, record, processInstanceID), nil
	}
	if request.Workflow.Operation == "observe" {
		return protocolmodel.WithoutSecrets(result), nil
	}
	return protocolmodel.EnforceSecretPolicy(result), nil
}

// Handle executes one workflow transition. Callers must decode and validate
// the wire request before dispatching it here.
func (coordinator *Coordinator) Handle(ctx context.Context, request protocolmodel.AcquireRequest, environment Environment) (protocolmodel.Response, error) {
	switch request.Workflow.Operation {
	case "prepare":
		return coordinator.prepare(request, environment)
	case "observe", "finalize", "cancel":
		return coordinator.sessionRequest(ctx, request, environment)
	default:
		return protocolmodel.Response{}, errors.New("workflow.operation 不受支持")
	}
}
