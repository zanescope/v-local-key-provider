//go:build darwin

package shadowfixture

import (
	commandmodel "github.com/zanescope/v-local-key-provider/internal/command"
	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

// NewRunner is always production-disabled. It gives real daemon framing a
// deterministic, non-WeChat route for automated vertical acceptance.
func NewRunner() commandmodel.ShadowRunner {
	clock := clockmodel.System{}
	credential := Credential()
	adapter := &shadowmodel.SyntheticAdapter{
		Clock: clock, BuildSet: SyntheticBuildDigest, SourceDigest: SyntheticSourceDigest,
		SourceVersion: "4.1.11-synthetic", SourceBuild: "26000-synthetic", ProcessPID: 2_147_483_646,
		Credential: credential, Expected: append([]byte(nil), credential...),
		FailBefore: map[string]string{}, FailAfter: map[string]string{}, AdvanceByStage: map[string]uint64{},
	}
	coordinator, err := shadowmodel.NewCoordinator(shadowmodel.Config{
		BuildSetDigest: SyntheticBuildDigest, CleanupRoute: contract.CleanupRouteDirect,
		ProductionRouteEnabled: false, SyntheticRouteEnabled: true, ExpectedSecurityPosture: "synthetic",
		Clock: clock, Journal: shadowmodel.NewMemoryJournal(), Locker: &shadowmodel.MemoryLocker{},
		Adapter: adapter, Cleanup: adapter,
	})
	if err != nil {
		return nil
	}
	return coordinator
}
