package provider

import diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"

type diagnostics = diagnosticmodel.Diagnostics

func newDiagnosticSchema(platform string, scopes []string) diagnostics {
	return diagnosticmodel.New(platform, scopes, defaultSecurityPostureStatus())
}

func canonicalRequestedScopes(scopes []string) []string {
	return diagnosticmodel.CanonicalScopes(scopes)
}

type diagnosticOutcome struct {
	resultCode            string
	workflowStatus        string
	nextAction            string
	blockingReasons       []string
	securityPostureStatus string
	shadowRouteStatus     string
}

type diagnosticDecisionContext struct {
	diagnostics               diagnostics
	databaseComplete          bool
	mediaComplete             bool
	options                   acquireOptions
	shadowFallbackReason      string
	sipDisabledRouteAttempted bool
}

type diagnosticOutcomeRule struct {
	name    string
	matches func(diagnosticDecisionContext) bool
	decide  func(diagnosticDecisionContext) diagnosticOutcome
}

func diagnosticModelContext(context diagnosticDecisionContext) diagnosticmodel.DecisionContext {
	return diagnosticmodel.DecisionContext{
		Diagnostics: context.diagnostics, DatabaseComplete: context.databaseComplete,
		MediaComplete: context.mediaComplete, BudgetExpired: context.options.budget.expired(),
		DatabaseRequested: context.options.database, ShadowFallbackReason: context.shadowFallbackReason,
		SIPDisabledRouteAttempted: context.sipDisabledRouteAttempted,
	}
}

func diagnosticOutcomeFromModel(outcome diagnosticmodel.Outcome) diagnosticOutcome {
	return diagnosticOutcome{
		resultCode: outcome.ResultCode, workflowStatus: outcome.WorkflowStatus,
		nextAction: outcome.NextAction, blockingReasons: outcome.BlockingReasons,
		securityPostureStatus: outcome.SecurityPostureStatus, shadowRouteStatus: outcome.ShadowRouteStatus,
	}
}

func fixedDiagnosticOutcome(context diagnosticDecisionContext, resultCode, workflowStatus, nextAction string, reasons ...string) diagnosticOutcome {
	return diagnosticOutcomeFromModel(diagnosticmodel.FixedOutcome(
		diagnosticModelContext(context), resultCode, workflowStatus, nextAction, reasons...,
	))
}

func newDiagnosticOutcomeRules() []diagnosticOutcomeRule {
	rules := diagnosticmodel.OutcomeRules()
	result := make([]diagnosticOutcomeRule, 0, len(rules))
	for _, internalRule := range rules {
		rule := internalRule
		result = append(result, diagnosticOutcomeRule{
			name: rule.Name,
			matches: func(context diagnosticDecisionContext) bool {
				return rule.Matches(diagnosticModelContext(context))
			},
			decide: func(context diagnosticDecisionContext) diagnosticOutcome {
				return diagnosticOutcomeFromModel(rule.Decide(diagnosticModelContext(context)))
			},
		})
	}
	return result
}

var diagnosticOutcomeRules = newDiagnosticOutcomeRules()

func resolveDiagnosticOutcome(diag diagnostics, databaseComplete, mediaComplete bool, options acquireOptions) diagnosticOutcome {
	context := diagnosticDecisionContext{
		diagnostics: diag, databaseComplete: databaseComplete, mediaComplete: mediaComplete, options: options,
		shadowFallbackReason:      shadowRouteFallbackReason(diag.ShadowRouteStatus),
		sipDisabledRouteAttempted: diag.Platform == "darwin" && darwinSIPDisabledRouteAttempted(diag.RoutesAttempted),
	}
	return diagnosticOutcomeFromModel(diagnosticmodel.ResolveOutcome(diagnosticModelContext(context)))
}

func applyDiagnosticOutcome(diag *diagnostics, outcome diagnosticOutcome) {
	diagnosticmodel.ApplyOutcome(diag, diagnosticmodel.Outcome{
		ResultCode: outcome.resultCode, WorkflowStatus: outcome.workflowStatus,
		NextAction: outcome.nextAction, BlockingReasons: outcome.blockingReasons,
		SecurityPostureStatus: outcome.securityPostureStatus, ShadowRouteStatus: outcome.shadowRouteStatus,
	})
}

func applyFixedDiagnosticOutcome(diag *diagnostics, resultCode, workflowStatus, nextAction string, reasons ...string) {
	context := diagnosticDecisionContext{diagnostics: *diag}
	applyDiagnosticOutcome(diag, fixedDiagnosticOutcome(context, resultCode, workflowStatus, nextAction, reasons...))
}
