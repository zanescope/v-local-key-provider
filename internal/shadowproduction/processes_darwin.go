//go:build darwin && cgo

package shadowproduction

import (
	"context"
	"errors"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowprocess "github.com/zanescope/v-local-key-provider/internal/shadowprocess"
)

// SystemProcesses independently re-observes only the exact journaled process
// identities. It never scans by process name, bundle ID, or executable prefix.
type SystemProcesses struct{}

func (SystemProcesses) Absent(ctx context.Context, record shadowmodel.RecoveryRecord) (ProcessFacts, error) {
	if ctx == nil || ctx.Err() != nil || record.Validate() != nil {
		return ProcessFacts{}, errors.New("production process absence binding is invalid")
	}
	facts := ProcessFacts{ProcessAbsent: true, SupervisorAbsent: true}
	if record.Process != nil {
		absent, err := shadowprocess.Absent(record.Process.PID, record.Process.StartMonotonicNS)
		if err != nil {
			return ProcessFacts{}, err
		}
		facts.ProcessAbsent = absent
	}
	if err := ctx.Err(); err != nil {
		return ProcessFacts{}, err
	}
	if record.Supervisor != nil {
		absent, err := shadowprocess.Absent(record.Supervisor.PID, record.Supervisor.StartMonotonicNS)
		if err != nil {
			return ProcessFacts{}, err
		}
		facts.SupervisorAbsent = absent
	}
	return facts, nil
}
