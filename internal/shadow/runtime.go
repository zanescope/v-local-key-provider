package shadow

import (
	"context"

	clockmodel "github.com/zanescope/v-local-key-provider/internal/shadowclock"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type Adapter interface {
	Qualify(context.Context, contract.Request) (contract.Qualification, SourceBinding, error)
	Requalify(context.Context, contract.Request) (SourceBinding, error)
	CreateWorkspace(context.Context, RecoveryRecord) ([]contract.ResourceBinding, error)
	Transform(context.Context, RecoveryRecord) error
	SupervisorArtifact(context.Context, RecoveryRecord) (contract.ResourceBinding, error)
	CreateCaptureLeaves(context.Context, RecoveryRecord) ([]contract.ResourceBinding, error)
	RegisterLaunch(context.Context, RecoveryRecord) error
	CreateContainer(context.Context, RecoveryRecord) (contract.ResourceBinding, error)
	PrepareLaunch(
		context.Context,
		RecoveryRecord,
		func(SupervisorProcessBinding) error,
		func(contract.ProcessBinding) error,
	) (contract.ProcessBinding, error)
	ReleaseLaunch(context.Context, RecoveryRecord) error
	Capture(context.Context, RecoveryRecord) ([]byte, error)
	ValidateCredential([]byte) error
}

// CleanupExecutor is frozen into the build-set and recovery contract. It only
// accepts exact identities already bound by the coordinator; an attempt cannot
// switch cleanup routes after mutation has started.
type CleanupExecutor interface {
	Route() string
	StopCapture(context.Context, RecoveryRecord) error
	StopSupervisor(context.Context, RecoveryRecord) (bool, error)
	UnregisterLaunch(context.Context, RecoveryRecord) error
	RemoveContainer(context.Context, RecoveryRecord) error
	RemoveLeaves(context.Context, RecoveryRecord) error
	RemoveWorkspace(context.Context, RecoveryRecord) error
	VerifyCleanup(context.Context, RecoveryRecord) (contract.CleanupFacts, error)
}

type Config struct {
	BuildSetDigest          string
	CleanupRoute            string
	ProductionRouteEnabled  bool
	SyntheticRouteEnabled   bool
	ExpectedSecurityPosture string
	Clock                   clockmodel.Clock
	Journal                 Journal
	Locker                  Locker
	Adapter                 Adapter
	Cleanup                 CleanupExecutor
	NewID                   func() (string, error)
}

type Output struct {
	Result     contract.Result
	Credential []byte
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
