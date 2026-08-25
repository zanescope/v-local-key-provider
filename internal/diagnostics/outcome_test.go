package diagnostics

import "testing"

func TestOutcomeRulePriorityAndDefaultAreStable(t *testing.T) {
	expected := []string{
		"helper_untrusted", "process_identity_untrusted", "sip_restoration", "account_mismatch",
		"wechat_not_running", "complete", "hook_trigger_required", "hook_restart_required",
		"hook_relogin_required", "sip_fallback_available", "sip_posture_unverified", "shadow_approval",
		"sip_route_unresolved", "process_access_denied", "validator_conflict", "candidate_ambiguous",
		"deadline_exhausted", "database_targets_not_found", "partial_default",
	}
	rules := OutcomeRules()
	if len(rules) != len(expected) {
		t.Fatalf("unexpected rule count: %d", len(rules))
	}
	for index, name := range expected {
		if rules[index].Name != name {
			t.Fatalf("rule %d = %q, want %q", index, rules[index].Name, name)
		}
	}
	if !rules[len(rules)-1].Matches(DecisionContext{}) {
		t.Fatal("final outcome rule is not unconditional")
	}
}

func TestOutcomePriorityFailsClosedBeforeComplete(t *testing.T) {
	context := DecisionContext{
		Diagnostics:      Diagnostics{HelperStatus: "untrusted"},
		DatabaseComplete: true, MediaComplete: true,
	}
	outcome := ResolveOutcome(context)
	if outcome.ResultCode != "unsupported" || outcome.WorkflowStatus != "blocked" || outcome.NextAction != "stop_and_report" {
		t.Fatalf("untrusted helper did not outrank completion: %+v", outcome)
	}
}

func TestSIPRestorationRequiresRouteEvidenceWhenCoverageIsIncomplete(t *testing.T) {
	outcome := ResolveOutcome(DecisionContext{
		Diagnostics: Diagnostics{Platform: "darwin", SecurityPostureStatus: "sip_disabled_verified"},
	})
	if outcome.SecurityPostureStatus != "restoration_required" || len(outcome.BlockingReasons) != 1 || outcome.BlockingReasons[0] != "sip_disabled_route_not_attempted" {
		t.Fatalf("unexpected SIP restoration outcome: %+v", outcome)
	}
}
