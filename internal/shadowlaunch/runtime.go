// Package shadowlaunch binds LaunchServices operations to one journaled clone
// path and one attempt-random bundle identifier. Discovery by process name,
// application name, or bundle-ID prefix is intentionally absent.
package shadowlaunch

import (
	"context"
	"errors"
	"path/filepath"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowcleanup "github.com/zanescope/v-local-key-provider/internal/shadowcleanup"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

type Runtime struct {
	Register        func(context.Context, string, string) error
	Unregister      func(context.Context, string, string) error
	RegisteredPaths func(context.Context, string) ([]string, error)
}

func (value Runtime) Validate() error {
	if value.Register == nil || value.Unregister == nil || value.RegisteredPaths == nil {
		return errors.New("Shadow launch runtime is incomplete")
	}
	return nil
}

func exactIdentity(record shadowmodel.RecoveryRecord) bool {
	return len(record.AttemptID) == 32 && record.RootLeaf == "attempt-"+record.AttemptID &&
		record.BundleID == "com.zanescope.vlocal.shadow."+record.AttemptID
}

func cloneResource(record shadowmodel.RecoveryRecord) (contract.ResourceBinding, bool) {
	expected := filepath.ToSlash(filepath.Join(record.RootLeaf, "WeChat.app"))
	for _, resource := range record.Resources {
		if resource.Kind == "clone_app" && resource.Leaf == expected {
			return resource, true
		}
	}
	return contract.ResourceBinding{}, false
}

func sameDirectory(left, right contract.ResourceBinding) bool {
	return left.Kind == right.Kind && left.Leaf == right.Leaf && left.Device == right.Device &&
		left.Inode == right.Inode && left.UID == right.UID && left.Mode == right.Mode && left.LinkCount == right.LinkCount
}

func (value Runtime) exactClone(account shadowaccount.Record, record shadowmodel.RecoveryRecord) (string, error) {
	if value.Validate() != nil || shadowaccount.Revalidate(account) != nil || !exactIdentity(record) {
		return "", errors.New("Shadow launch binding is invalid")
	}
	expected, found := cloneResource(record)
	if !found {
		return "", errors.New("Shadow launch lacks a journaled clone")
	}
	workspace := filepath.Join(account.SecurityRoot, record.RootLeaf)
	current, err := shadowcleanup.BindDirectory(workspace, "WeChat.app", "clone_app")
	if err != nil {
		return "", err
	}
	current.Leaf = filepath.ToSlash(filepath.Join(record.RootLeaf, "WeChat.app"))
	if !sameDirectory(current, expected) {
		return "", errors.New("Shadow launch clone identity drifted")
	}
	clone := filepath.Join(workspace, "WeChat.app")
	resolved, err := filepath.EvalSymlinks(clone)
	if err != nil || resolved != clone {
		return "", errors.New("Shadow launch clone path is not canonical")
	}
	return clone, nil
}

func exactRegistration(paths []string, expected string) bool {
	if len(paths) != 1 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(paths[0])
	return err == nil && filepath.IsAbs(paths[0]) && filepath.Clean(paths[0]) == paths[0] &&
		resolved == paths[0] && paths[0] == expected
}

func (value Runtime) RegisterExact(ctx context.Context, account shadowaccount.Record, record shadowmodel.RecoveryRecord) error {
	clone, err := value.exactClone(account, record)
	if err != nil || ctx == nil {
		return errors.New("Shadow launch registration binding is invalid")
	}
	paths, err := value.RegisteredPaths(ctx, record.BundleID)
	if err != nil || len(paths) != 0 {
		return errors.New("Shadow launch random identity is already registered")
	}
	if err := value.Register(ctx, clone, record.BundleID); err != nil {
		return err
	}
	paths, err = value.RegisteredPaths(ctx, record.BundleID)
	if err != nil || !exactRegistration(paths, clone) {
		return errors.New("Shadow launch registration was not exact")
	}
	return nil
}

func (value Runtime) UnregisterExact(ctx context.Context, account shadowaccount.Record, record shadowmodel.RecoveryRecord) error {
	if value.Validate() != nil || ctx == nil || !exactIdentity(record) {
		return errors.New("Shadow launch unregistration binding is invalid")
	}
	paths, err := value.RegisteredPaths(ctx, record.BundleID)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}
	clone, err := value.exactClone(account, record)
	if err != nil || !exactRegistration(paths, clone) {
		return errors.New("Shadow launch unregistration binding is invalid")
	}
	if err := value.Unregister(ctx, clone, record.BundleID); err != nil {
		return err
	}
	paths, err = value.RegisteredPaths(ctx, record.BundleID)
	if err != nil || len(paths) != 0 {
		return errors.New("Shadow launch registration residue remains")
	}
	return nil
}

func (value Runtime) Absent(ctx context.Context, record shadowmodel.RecoveryRecord) bool {
	if value.Validate() != nil || ctx == nil || !exactIdentity(record) {
		return false
	}
	paths, err := value.RegisteredPaths(ctx, record.BundleID)
	return err == nil && len(paths) == 0
}
