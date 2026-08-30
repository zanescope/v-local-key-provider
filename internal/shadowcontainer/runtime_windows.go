//go:build windows

package shadowcontainer

import (
	"context"
	"errors"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type Runtime struct{}

func (Runtime) Create(context.Context, shadowaccount.Record, shadowmodel.RecoveryRecord) (contract.ResourceBinding, error) {
	return contract.ResourceBinding{}, errors.New("Shadow containers are unavailable on Windows")
}
func (Runtime) Remove(context.Context, shadowaccount.Record, shadowmodel.RecoveryRecord) error {
	return errors.New("Shadow containers are unavailable on Windows")
}
func (Runtime) Absent(shadowaccount.Record, shadowmodel.RecoveryRecord) bool { return false }
