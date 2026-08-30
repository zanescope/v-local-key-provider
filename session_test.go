package provider

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sessionmodel "github.com/zanescope/v-local-key-provider/internal/session"
)

func sessionRequestFixture(t *testing.T, operation string) acquireRequest {
	t.Helper()
	account := t.TempDir()
	dbDir := filepath.Join(account, "db_storage")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "message.db"), bytes.Repeat([]byte{0x42}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	return acquireRequest{
		Protocol: protocolName, RequestID: "request-1", Action: "acquire",
		AccountDir: account, DBDir: dbDir, Scopes: []string{"database"}, DeadlineMS: 30_000,
		Workflow: workflowRequest{Operation: operation},
	}
}

func requireSessionSnapshot(t *testing.T, store *acquisitionSessionStore, id string) *acquisitionSession {
	t.Helper()
	session := store.sessionSnapshot(id)
	if session == nil {
		t.Fatalf("session %q is not active", id)
	}
	return session
}

func mutateSessionFixture(t *testing.T, store *acquisitionSessionStore, id string, mutate func(*acquisitionSession)) *acquisitionSession {
	t.Helper()
	if !store.mutateSession(id, mutate) {
		t.Fatalf("session %q is not active", id)
	}
	return requireSessionSnapshot(t, store, id)
}

func TestSessionPrepareBindsCatalogAndCancelRemovesSession(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.CatalogID == "" || prepared.Diagnostics.SessionID == "" || prepared.Diagnostics.WorkflowStatus != "running" {
		t.Fatalf("prepare response missing session binding: %+v", prepared)
	}
	cancel := request
	cancel.RequestID = "request-2"
	cancel.Workflow = workflowRequest{Operation: "cancel", SessionID: prepared.Diagnostics.SessionID}
	cancelled, err := store.handle(cancel)
	if err != nil || cancelled.Diagnostics.ResultCode != "cancelled" {
		t.Fatalf("cancel failed: response=%+v err=%v", cancelled, err)
	}
	if store.activeCount() != 0 {
		t.Fatal("cancelled session remained in memory")
	}
}

func TestSessionRejectsCatalogDriftBeforeAcquisition(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(request.DBDir, "message.db")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x24}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	observe := request
	observe.RequestID = "request-2"
	observe.Workflow = workflowRequest{
		Operation: "observe", SessionID: prepared.Diagnostics.SessionID,
		ExpectedCatalogID: prepared.CatalogID,
	}
	result, err := store.handle(observe)
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.WorkflowStatus != "blocked" || len(result.Diagnostics.BlockingReasons) != 1 || result.Diagnostics.BlockingReasons[0] != "catalog_drift" {
		t.Fatalf("catalog drift was not blocked: %+v", result.Diagnostics)
	}
}

func TestSessionRejectsDuplicateActionReceiptWithoutStateChange(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	// Duplicate-receipt policy is independent of the user's live WeChat process.
	// Freeze this fixture's observation so a real login/restart cannot turn the
	// same-process test into a machine-state race.
	runtime := inertAcquisitionSessionRuntime()
	runtime.ProcessInstanceID = func() string { return "stable-process-instance" }
	store.coordinator = sessionmodel.NewCoordinator(store.core, runtime)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.LastActionStage = "trigger_database"
	})
	receipt := &actionReceipt{
		Action: "trigger_database", UserConfirmed: true, ObservedProcessTransition: "same_process",
		ProcessInstanceID: session.ProcessInstanceID, ActionStage: "trigger_database",
	}
	fingerprint, err := sessionmodel.ReceiptFingerprint(receipt, sessionmodel.ReceiptState{
		CatalogID: session.CatalogID, ProcessInstanceID: session.ProcessInstanceID,
		LastRoute: session.LastRoute, LastActionStage: session.LastActionStage,
	}, "stable-process-instance")
	if err != nil {
		t.Fatal(err)
	}
	mutateSessionFixture(t, store, session.ID, func(session *acquisitionSession) {
		session.Receipts[fingerprint] = true
	})
	observe := request
	observe.RequestID = "request-2"
	observe.Workflow = workflowRequest{
		Operation: "observe", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID,
		ActionReceipt: receipt,
	}
	result, err := store.handle(observe)
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.WorkflowStatus != "blocked" || result.Diagnostics.BlockingReasons[0] != "duplicate_action_without_state_change" {
		t.Fatalf("duplicate action was not blocked: %+v", result.Diagnostics)
	}
}

func TestSessionRejectsSensitiveOrCallerControlledActionReceipt(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.LastActionStage = "trigger_database"
	})
	observe := request
	observe.RequestID = "request-2"
	observe.Workflow = workflowRequest{
		Operation: "observe", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID,
		ActionReceipt: &actionReceipt{
			Action: "disable_sip", UserConfirmed: true, ProcessInstanceID: session.ProcessInstanceID,
			Route: "caller-controlled", ActionStage: "disable_sip",
		},
	}
	result, err := store.handle(observe)
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.WorkflowStatus != "blocked" || result.Diagnostics.BlockingReasons[0] != "action_receipt_rejected" {
		t.Fatalf("sensitive receipt was not rejected: %+v", result.Diagnostics)
	}
}

func TestSessionRequiresExplicitReceiptForPendingAction(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.LastActionStage = "restart_wechat"
		session.Latest = &response{
			Protocol: protocolName, CatalogID: prepared.CatalogID,
			DatabaseKeys: map[string]string{"message.db": strings.Repeat("a", 64)},
			Diagnostics: diagnostics{
				ResultCode: "action_required", WorkflowStatus: "waiting_action", DatabaseCoverageStatus: "partial",
				NextAction: "restart_wechat", ActionStage: "restart_wechat",
			},
		}
	})
	observe := request
	observe.RequestID = "request-2"
	observe.Workflow = workflowRequest{Operation: "observe", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID}
	result, err := store.handle(observe)
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.NextAction != "restart_wechat" || result.DatabaseKeys != nil || result.DatabaseCredential != nil {
		t.Fatalf("pending action did not stay secret-free and waiting: %+v", result)
	}
}

func TestFinalizeWithoutActionReceiptReturnsVerifiedPartialAndEndsSession(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 64)
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.LastActionStage = "trigger_database"
		session.Latest = &response{
			Protocol: protocolName, CatalogID: prepared.CatalogID,
			DatabaseKeys:     map[string]string{"message.db": key},
			DatabaseProfiles: map[string]string{"message.db": defaultProfileID},
			Diagnostics: diagnostics{
				ResultCode: "action_required", WorkflowStatus: "waiting_action", DatabaseCoverageStatus: "partial",
				NextAction: "trigger_database", ActionStage: "trigger_database",
			},
		}
	})
	finalize := request
	finalize.RequestID = "request-stop-and-report"
	finalize.Workflow = workflowRequest{Operation: "finalize", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID}
	result, err := store.handle(finalize)
	if err != nil {
		t.Fatal(err)
	}
	if result.DatabaseKeys["message.db"] != key || result.Diagnostics.ResultCode != "partial" ||
		result.Diagnostics.WorkflowStatus != "terminal" || result.Diagnostics.NextAction != "none" ||
		len(result.Diagnostics.BlockingReasons) != 1 || result.Diagnostics.BlockingReasons[0] != "user_declined_action" {
		t.Fatalf("explicit partial finalization lost verified evidence: %+v", result)
	}
	if store.hasSession(session.ID) {
		t.Fatal("partial finalization left the acquisition session active")
	}
}

func TestFinalizeWithoutReceiptDoesNotConvertAccountMismatchToPartial(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 64)
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.LastActionStage = "switch_to_target_account"
		session.Latest = &response{
			Protocol: protocolName, CatalogID: prepared.CatalogID,
			DatabaseKeys:     map[string]string{"message.db": key},
			DatabaseProfiles: map[string]string{"message.db": defaultProfileID},
			DatabaseCredential: &databaseCredential{
				Mode: "per_database", Overrides: map[string]credentialOverride{
					"db": {Kind: "raw_enc_key", ProfileID: defaultProfileID, Secret: key, RelativePath: "message.db"},
				},
			},
			ImageKeys: &imageKeys{AES: "1234567890abcdef", XOR: 7},
			Diagnostics: diagnostics{
				ResultCode: "action_required", WorkflowStatus: "waiting_action", NextAction: "switch_to_target_account",
				ActionStage: "switch_to_target_account", BlockingReasons: []string{"account_mismatch"},
				DatabaseCoverageStatus: "complete", TargetBindingStatus: "mismatch", SessionAccountStatus: "known_other",
			},
		}
	})

	finalize := request
	finalize.RequestID = "request-stop-mismatch"
	finalize.Workflow = workflowRequest{Operation: "finalize", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID}
	result, err := store.handle(finalize)
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.ResultCode != "action_required" || result.Diagnostics.WorkflowStatus != "waiting_action" ||
		result.Diagnostics.NextAction != "switch_to_target_account" || result.Diagnostics.TargetBindingStatus != "mismatch" {
		t.Fatalf("account mismatch was converted into a terminal partial: %+v", result.Diagnostics)
	}
	if result.DatabaseKeys != nil || result.DatabaseProfiles != nil || result.DatabaseCredential != nil || result.ImageKeys != nil {
		t.Fatalf("account mismatch response leaked session secrets: %+v", result)
	}
	if !store.hasSession(session.ID) {
		t.Fatal("account mismatch finalize unexpectedly destroyed the actionable session")
	}
}

func TestClosedSessionStoreRejectsNewPrepare(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	store.closeAll()
	if _, err := store.handle(sessionRequestFixture(t, "prepare")); err == nil {
		t.Fatal("closed session store accepted a new prepare request")
	}
}

func TestSessionRejectsUnboundOrConcurrentObserve(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	session := requireSessionSnapshot(t, store, prepared.Diagnostics.SessionID)
	observe := request
	observe.RequestID = "request-unbound"
	observe.Workflow = workflowRequest{Operation: "observe", SessionID: session.ID}
	if _, err := store.handle(observe); err == nil {
		t.Fatal("observe without expected_catalog_id was accepted")
	}
	mutateSessionFixture(t, store, session.ID, func(session *acquisitionSession) {
		session.InFlight = true
	})
	observe.RequestID = "request-concurrent"
	observe.Workflow.ExpectedCatalogID = prepared.CatalogID
	result, err := store.handle(observe)
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.WorkflowStatus != "blocked" || result.Diagnostics.BlockingReasons[0] != "acquisition_request_in_progress" {
		t.Fatalf("concurrent observe was not serialized: %+v", result.Diagnostics)
	}
}

func TestSessionRejectsDifferentVerifiedClientIdentity(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	request.PeerIdentity = "windows:c:/trusted/v-local-cli.exe"
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	observe := request
	observe.RequestID = "request-other-client"
	observe.PeerIdentity = "windows:c:/same-user/impostor.exe"
	observe.Workflow = workflowRequest{
		Operation: "observe", SessionID: prepared.Diagnostics.SessionID, ExpectedCatalogID: prepared.CatalogID,
	}
	if _, err := store.handle(observe); err == nil || !strings.Contains(err.Error(), "客户端身份不匹配") {
		t.Fatalf("session accepted a different verified client identity: %v", err)
	}
}

func TestFinalizeRechecksCatalogEvenWhenLatestResultExists(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.Latest = &response{CatalogID: prepared.CatalogID, DatabaseKeys: map[string]string{"message.db": strings.Repeat("a", 64)}}
	})
	if err := os.WriteFile(filepath.Join(request.DBDir, "message.db"), bytes.Repeat([]byte{0x24}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	finalize := request
	finalize.RequestID = "request-finalize"
	finalize.Workflow = workflowRequest{Operation: "finalize", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID}
	result, err := store.handle(finalize)
	if err != nil {
		t.Fatal(err)
	}
	if result.Diagnostics.WorkflowStatus != "blocked" || result.Diagnostics.BlockingReasons[0] != "catalog_drift" || result.DatabaseKeys != nil {
		t.Fatalf("finalize did not fail closed on catalog drift: %+v", result)
	}
}

func TestFinalizeReturnsTerminalSessionResultWithoutRepeatingAcquisition(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 64)
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.Latest = &response{
			CatalogID: prepared.CatalogID, DatabaseKeys: map[string]string{"message.db": key},
			DatabaseProfiles: map[string]string{"message.db": defaultProfileID},
			Diagnostics:      diagnostics{ResultCode: "partial", DatabaseCoverageStatus: "partial", WorkflowStatus: "terminal"},
		}
	})
	finalize := request
	finalize.RequestID = "request-terminal-finalize"
	finalize.Workflow = workflowRequest{Operation: "finalize", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID}
	result, err := store.handle(finalize)
	if err != nil {
		t.Fatal(err)
	}
	if result.DatabaseKeys["message.db"] != key || store.hasSession(session.ID) || result.Diagnostics.ActionStage != "finalize" {
		t.Fatalf("finalize repeated or lost terminal session evidence: %+v", result)
	}
}

func TestFinalizeReappliesSecretPolicyToCachedTerminalResult(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.Latest = &response{
			CatalogID:    prepared.CatalogID,
			DatabaseKeys: map[string]string{"message.db": strings.Repeat("a", 64)},
			Diagnostics:  diagnostics{ResultCode: "cancelled", WorkflowStatus: "terminal"},
		}
	})
	finalize := request
	finalize.RequestID = "request-unsafe-terminal-finalize"
	finalize.Workflow = workflowRequest{Operation: "finalize", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID}
	result, err := store.handle(finalize)
	if err != nil {
		t.Fatal(err)
	}
	if result.DatabaseKeys != nil {
		t.Fatalf("cached unsafe terminal outcome bypassed the finalize secret policy: %+v", result)
	}
}

func TestObserveKeepsSecretsInSessionUntilFinalize(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 64)
	session := mutateSessionFixture(t, store, prepared.Diagnostics.SessionID, func(session *acquisitionSession) {
		session.Latest = &response{
			CatalogID: prepared.CatalogID, DatabaseKeys: map[string]string{"message.db": key},
			DatabaseProfiles: map[string]string{"message.db": defaultProfileID},
			DatabaseCredential: &databaseCredential{
				Mode: "per_database", CredentialEpoch: "epoch", Overrides: map[string]credentialOverride{
					"db": {Kind: "raw_enc_key", ProfileID: defaultProfileID, Secret: key, RelativePath: "message.db"},
				},
			},
			ImageKeys: &imageKeys{AES: "1234567890abcdef", XOR: 7},
		}
	})
	observe := request
	observe.RequestID = "request-observe"
	observe.Workflow = workflowRequest{Operation: "observe", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID}
	observed, err := store.handle(observe)
	if err != nil {
		t.Fatal(err)
	}
	if observed.DatabaseKeys != nil || observed.DatabaseProfiles != nil || observed.DatabaseCredential != nil || observed.ImageKeys != nil {
		t.Fatalf("observe leaked session secrets: %+v", observed)
	}
	finalize := request
	finalize.RequestID = "request-finalize"
	finalize.Workflow = workflowRequest{Operation: "finalize", SessionID: session.ID, ExpectedCatalogID: prepared.CatalogID}
	finalized, err := store.handle(finalize)
	if err != nil {
		t.Fatal(err)
	}
	if finalized.DatabaseKeys["message.db"] != key || finalized.DatabaseCredential == nil || finalized.ImageKeys == nil {
		t.Fatalf("finalize did not return the verified session secrets: %+v", finalized)
	}
	if store.activeCount() != 0 {
		t.Fatal("finalized session remained in memory")
	}
}

func TestSessionExpiresAtHardLifetime(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	base := time.Now()
	store.setClock(func() time.Time { return base })
	request := sessionRequestFixture(t, "prepare")
	prepared, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	store.setClock(func() time.Time { return base.Add(acquisitionSessionMaxLifetime + time.Second) })
	request.Workflow = workflowRequest{Operation: "cancel", SessionID: prepared.Diagnostics.SessionID}
	if _, err := store.handle(request); err == nil {
		t.Fatal("expired session should not be reusable")
	}
}

func TestSecondPrepareDoesNotDestroyActiveAccountSession(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	request := sessionRequestFixture(t, "prepare")
	first, err := store.handle(request)
	if err != nil {
		t.Fatal(err)
	}
	request.RequestID = "second-prepare"
	if _, err := store.handle(request); err == nil {
		t.Fatal("second prepare for the same account should report a conflict")
	}
	if !store.hasSession(first.Diagnostics.SessionID) || store.activeCount() != 1 {
		t.Fatal("second prepare destroyed the active account session")
	}
}

func TestDaemonAcceptsFramedPrepareRequest(t *testing.T) {
	request := sessionRequestFixture(t, "prepare")
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	var output bytes.Buffer
	if err := runTestAcquisitionDaemon(bytes.NewReader(payload), &output); err != nil {
		t.Fatal(err)
	}
	var result response
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Diagnostics.SessionID == "" || result.Protocol != protocolName {
		t.Fatalf("daemon prepare response invalid: response=%+v err=%v raw=%s", result, err, output.String())
	}
}
