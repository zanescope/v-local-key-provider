package provider

import sessionmodel "github.com/zanescope/v-local-key-provider/internal/session"

func receiptFingerprint(receipt *actionReceipt, session *acquisitionSession, currentProcessInstanceID string) (string, error) {
	return sessionmodel.ReceiptFingerprint(receipt, sessionmodel.ReceiptState{
		CatalogID: session.CatalogID, ProcessInstanceID: session.ProcessInstanceID,
		LastRoute: session.LastRoute, LastActionStage: session.LastActionStage,
	}, currentProcessInstanceID)
}

func sameScopes(left, right []string) bool {
	return sessionmodel.SameScopes(left, right)
}

func missingCatalog(catalog databaseCatalog, existing map[string]string) (databaseCatalog, map[string]bool) {
	return sessionmodel.MissingCatalog(catalog, existing)
}

func appendUniqueStrings(values []string, additions ...string) []string {
	return sessionmodel.AppendUniqueStrings(values, additions...)
}

func cloneDatabaseCredential(value *databaseCredential) *databaseCredential {
	return sessionmodel.CloneDatabaseCredential(value)
}

func mergeDatabaseCredentials(existing, next *databaseCredential) *databaseCredential {
	return sessionmodel.MergeDatabaseCredentials(existing, next)
}

func mergeSessionResults(existing *response, next response) response {
	return sessionmodel.MergeResults(existing, next)
}

func phase2SessionAction(action string) bool {
	return sessionmodel.IsAction(action)
}

func phase2PartialFinalizeAction(action string) bool {
	return sessionmodel.IsPartialFinalizeAction(action)
}

func phase2ActionRetryLimit(action string) int {
	return sessionmodel.ActionRetryLimit(action)
}

func responseWithoutSecrets(value response) response {
	return sessionmodel.WithoutSecrets(value)
}

func diagnosticsHaveCompleteRequestedCoverage(diag diagnostics) bool {
	return sessionmodel.HasCompleteRequestedCoverage(diag)
}

func diagnosticsPermitSecrets(diag diagnostics) bool {
	return sessionmodel.DiagnosticsPermitSecrets(diag)
}

func enforceResponseSecretPolicy(value response) response {
	return sessionmodel.EnforceSecretPolicy(value)
}

func terminalEmptyCoverageStatuses(scopes []string) (string, string) {
	return sessionmodel.TerminalEmptyCoverageStatuses(scopes)
}

func databaseTargetStatus(scopes []string, latest *response) string {
	return sessionmodel.DatabaseTargetStatus(scopes, latest)
}
