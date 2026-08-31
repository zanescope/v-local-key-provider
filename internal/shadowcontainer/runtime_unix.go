//go:build !windows

// Package shadowcontainer owns only attempt-bound container directories. It
// never discovers, copies, migrates, or removes an original application
// container.
package shadowcontainer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowcleanup "github.com/zanescope/v-local-key-provider/internal/shadowcleanup"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type Runtime struct {
	// revalidate is an unexported test seam. Production always uses the
	// platform account database revalidation below; Unix compatibility tests
	// can exercise exact filesystem ownership without pretending Linux has the
	// macOS account database contract.
	revalidate func(shadowaccount.Record) error
}

func (value Runtime) revalidateAccount(account shadowaccount.Record) error {
	if value.revalidate != nil {
		return value.revalidate(account)
	}
	return shadowaccount.Revalidate(account)
}

func exactIdentity(record shadowmodel.RecoveryRecord) bool {
	return len(record.AttemptID) == 32 && record.BundleID == "com.zanescope.vlocal.shadow."+record.AttemptID &&
		!strings.ContainsAny(record.BundleID, "/\\\x00")
}

func boundContainer(record shadowmodel.RecoveryRecord) (contract.ResourceBinding, bool) {
	for _, resource := range record.Resources {
		if resource.Kind == "container" && resource.Leaf == record.BundleID {
			return resource, true
		}
	}
	return contract.ResourceBinding{}, false
}

func (value Runtime) Create(ctx context.Context, account shadowaccount.Record, record shadowmodel.RecoveryRecord) (contract.ResourceBinding, error) {
	if ctx == nil || !exactIdentity(record) || value.revalidateAccount(account) != nil {
		return contract.ResourceBinding{}, errors.New("Shadow container creation binding is invalid")
	}
	return shadowcleanup.CreateExactDirectory(ctx, account.ContainersRoot, record.BundleID, "container")
}

func (value Runtime) Remove(ctx context.Context, account shadowaccount.Record, record shadowmodel.RecoveryRecord) error {
	if ctx == nil || !exactIdentity(record) || value.revalidateAccount(account) != nil {
		return errors.New("Shadow container cleanup binding is invalid")
	}
	binding, found := boundContainer(record)
	if !found {
		if _, err := os.Lstat(filepath.Join(account.ContainersRoot, record.BundleID)); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		var err error
		binding, err = shadowcleanup.BindDirectory(account.ContainersRoot, record.BundleID, "container")
		if err != nil {
			return err
		}
	}
	return shadowcleanup.RemoveExactDirectory(ctx, account.ContainersRoot, binding)
}

func (value Runtime) Absent(account shadowaccount.Record, record shadowmodel.RecoveryRecord) bool {
	if !exactIdentity(record) || value.revalidateAccount(account) != nil {
		return false
	}
	_, err := os.Lstat(filepath.Join(account.ContainersRoot, record.BundleID))
	return os.IsNotExist(err)
}
