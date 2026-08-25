package diagnostics

// Outcome is the complete protocol-level workflow decision derived from
// acquisition evidence.
type Outcome struct {
	ResultCode            string
	WorkflowStatus        string
	NextAction            string
	BlockingReasons       []string
	SecurityPostureStatus string
	ShadowRouteStatus     string
}

type DecisionContext struct {
	Diagnostics               Diagnostics
	DatabaseComplete          bool
	MediaComplete             bool
	BudgetExpired             bool
	DatabaseRequested         bool
	ShadowFallbackReason      string
	SIPDisabledRouteAttempted bool
}

type OutcomeRule struct {
	Name    string
	Matches func(DecisionContext) bool
	Decide  func(DecisionContext) Outcome
}

func FixedOutcome(context DecisionContext, resultCode, workflowStatus, nextAction string, reasons ...string) Outcome {
	return Outcome{
		ResultCode: resultCode, WorkflowStatus: workflowStatus, NextAction: nextAction,
		BlockingReasons:       append([]string(nil), reasons...),
		SecurityPostureStatus: context.Diagnostics.SecurityPostureStatus,
		ShadowRouteStatus:     context.Diagnostics.ShadowRouteStatus,
	}
}

var outcomeRules = []OutcomeRule{
	{
		Name: "helper_untrusted",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.HelperStatus == "untrusted" || context.Diagnostics.ProcessAccessError == "helper_untrusted"
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "unsupported", "blocked", "stop_and_report", "helper_untrusted")
		},
	},
	{
		Name: "process_identity_untrusted",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.ProcessAccessError == "process_identity_untrusted"
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "unsupported", "blocked", "stop_and_report", "process_identity_untrusted")
		},
	},
	{
		Name: "sip_restoration",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.Platform == "darwin" && context.Diagnostics.SecurityPostureStatus == "sip_disabled_verified"
		},
		Decide: func(context DecisionContext) Outcome {
			result := FixedOutcome(context, "action_required", "waiting_action", "reenable_sip")
			result.SecurityPostureStatus = "restoration_required"
			if !context.DatabaseComplete || !context.MediaComplete {
				if context.SIPDisabledRouteAttempted {
					result.BlockingReasons = []string{"sip_route_failed"}
				} else {
					result.BlockingReasons = []string{"sip_disabled_route_not_attempted"}
				}
			}
			return result
		},
	},
	{
		Name: "account_mismatch",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.TargetBindingStatus == "mismatch" || context.Diagnostics.SessionAccountStatus == "known_other"
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "action_required", "waiting_action", "switch_to_target_account", "account_mismatch")
		},
	},
	{
		Name: "wechat_not_running",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.ProcessAccessStatus == "wechat_not_running"
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "action_required", "waiting_action", "restart_wechat", "wechat_not_running")
		},
	},
	{
		Name: "complete",
		Matches: func(context DecisionContext) bool {
			return context.DatabaseComplete && context.MediaComplete
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "complete", "terminal", "none")
		},
	},
	{
		Name:    "hook_trigger_required",
		Matches: func(context DecisionContext) bool { return context.Diagnostics.HookTriggerRequired },
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "action_required", "waiting_action", "trigger_database", "hook_not_triggered")
		},
	},
	{
		Name:    "hook_restart_required",
		Matches: func(context DecisionContext) bool { return context.Diagnostics.HookRestartRequired },
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "action_required", "waiting_action", "restart_wechat", "database_open_required")
		},
	},
	{
		Name:    "hook_relogin_required",
		Matches: func(context DecisionContext) bool { return context.Diagnostics.HookReloginRequired },
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "action_required", "waiting_action", "relogin_wechat", "login_time_derivation_required")
		},
	},
	{
		Name: "sip_fallback_available",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.ProcessAccessStatus == "denied" && context.Diagnostics.ProcessAccessError == "sip_enabled" &&
				context.Diagnostics.SecurityPostureStatus == "sip_enabled_verified" && context.ShadowFallbackReason != ""
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "action_required", "waiting_action", "disable_sip", "standard_route_unavailable", context.ShadowFallbackReason)
		},
	},
	{
		Name: "sip_posture_unverified",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.ProcessAccessStatus == "denied" && context.Diagnostics.ProcessAccessError == "sip_enabled" &&
				context.Diagnostics.SecurityPostureStatus != "sip_enabled_verified"
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "unsupported", "blocked", "stop_and_report", "standard_route_unavailable", "security_posture_not_verified")
		},
	},
	{
		Name: "shadow_approval",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.ProcessAccessStatus == "denied" && context.Diagnostics.ProcessAccessError == "sip_enabled" &&
				(context.Diagnostics.ShadowRouteStatus == "available" || context.Diagnostics.ShadowRouteStatus == "awaiting_approval")
		},
		Decide: func(context DecisionContext) Outcome {
			result := FixedOutcome(context, "action_required", "waiting_action", "approve_shadow_mode", "standard_route_unavailable")
			result.ShadowRouteStatus = "awaiting_approval"
			return result
		},
	},
	{
		Name: "sip_route_unresolved",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.ProcessAccessStatus == "denied" && context.Diagnostics.ProcessAccessError == "sip_enabled"
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "unsupported", "blocked", "stop_and_report", "standard_route_unavailable", "shadow_route_not_evaluated")
		},
	},
	{
		Name: "process_access_denied",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.ProcessAccessStatus == "denied"
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "permission_required", "blocked", "fix_permission", "process_access_denied")
		},
	},
	{
		Name:    "validator_conflict",
		Matches: func(context DecisionContext) bool { return context.Diagnostics.ValidatorConflictCount > 0 },
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "failed", "blocked", "stop_and_report", "validator_conflict")
		},
	},
	{
		Name:    "candidate_ambiguous",
		Matches: func(context DecisionContext) bool { return context.Diagnostics.AmbiguousDatabaseKeys > 0 },
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "ambiguous", "blocked", "stop_and_report", "candidate_ambiguous")
		},
	},
	{
		Name: "deadline_exhausted",
		Matches: func(context DecisionContext) bool {
			return context.Diagnostics.BudgetExhausted || context.BudgetExpired
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "deadline_exhausted", "terminal", "stop_and_report", "deadline_exhausted")
		},
	},
	{
		Name: "database_targets_not_found",
		Matches: func(context DecisionContext) bool {
			return context.DatabaseRequested && context.Diagnostics.DatabaseTargetStatus == "none"
		},
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "partial", "terminal", "stop_and_report", "database_targets_not_found")
		},
	},
	{
		Name:    "partial_default",
		Matches: func(DecisionContext) bool { return true },
		Decide: func(context DecisionContext) Outcome {
			return FixedOutcome(context, "partial", "terminal", "stop_and_report")
		},
	},
}

func OutcomeRules() []OutcomeRule {
	return append([]OutcomeRule(nil), outcomeRules...)
}

func ResolveOutcome(context DecisionContext) Outcome {
	for _, rule := range outcomeRules {
		if rule.Matches(context) {
			return rule.Decide(context)
		}
	}
	panic("diagnostic outcome rules do not contain a terminal default")
}

func ApplyOutcome(diag *Diagnostics, outcome Outcome) {
	diag.ResultCode = outcome.ResultCode
	diag.WorkflowStatus = outcome.WorkflowStatus
	diag.NextAction = outcome.NextAction
	diag.BlockingReasons = append([]string{}, outcome.BlockingReasons...)
	diag.SecurityPostureStatus = outcome.SecurityPostureStatus
	diag.ShadowRouteStatus = outcome.ShadowRouteStatus
}
