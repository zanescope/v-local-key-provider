package provider

import diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"

type diagnostics = diagnosticmodel.Diagnostics

func platformDiagnosticDefaults() diagnosticmodel.PlatformDefaults {
	return diagnosticmodel.PlatformDefaults{
		SecurityPostureStatus: defaultSecurityPostureStatus(),
		// Shadow has no production implementation in the current build. Keep
		// this capability fact injected rather than inferred from the platform.
		DarwinShadowRouteStatus: "unavailable_in_build",
	}
}

func requestedScopes(database, media bool) []string {
	return diagnosticmodel.RequestedScopes(database, media)
}

func applyPlatformDiagnosticDefaults(diag *diagnostics) {
	diagnosticmodel.ApplyPlatformDefaults(diag, platformDiagnosticDefaults())
}

func newDiagnostics(platform string, scopes []string) diagnostics {
	return diagnosticmodel.NewWithPlatformDefaults(platform, scopes, platformDiagnosticDefaults())
}

func finalizeDiagnostics(diag *diagnostics, targets databaseTargets, result response, options acquireOptions) {
	diagnosticmodel.Finalize(diag, diagnosticmodel.FinalizeInput{
		Catalog: targets.Catalog, RequiredDatabaseCount: targets.Count,
		DatabaseKeys: result.DatabaseKeys, DatabaseCredential: result.DatabaseCredential,
		ImageKeysPresent:  result.ImageKeys != nil,
		DatabaseRequested: options.database, MediaRequested: options.media,
		BudgetExpired: options.budget.expired(), PlatformDefaults: platformDiagnosticDefaults(),
	})
}

func applyFixedDiagnosticOutcome(diag *diagnostics, resultCode, workflowStatus, nextAction string, reasons ...string) {
	diagnosticmodel.ApplyOutcome(diag, diagnosticmodel.FixedOutcome(
		diagnosticmodel.DecisionContext{Diagnostics: *diag},
		resultCode, workflowStatus, nextAction, reasons...,
	))
}
