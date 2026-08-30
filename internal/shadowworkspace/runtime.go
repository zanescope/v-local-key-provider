// Package shadowworkspace owns the pre-launch, one-shot APFS workspace. It
// creates only an attempt-bound directory and a CoW App clone; registration,
// containers, and processes belong to later adapters.
package shadowworkspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowcleanup "github.com/zanescope/v-local-key-provider/internal/shadowcleanup"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowinventory "github.com/zanescope/v-local-key-provider/internal/shadowinventory"
	shadowtransform "github.com/zanescope/v-local-key-provider/internal/shadowtransform"
)

const cloneLeaf = "WeChat.app"

type FilesystemIdentity struct {
	Device uint64
	Type   string
}

type DirectoryIdentity struct {
	Device    uint64
	Inode     uint64
	UID       uint32
	Mode      uint32
	LinkCount uint64
}

func (value DirectoryIdentity) valid() bool {
	return value.Device != 0 && value.Inode != 0 && value.Mode != 0 && value.LinkCount != 0
}

type Runtime struct {
	Clone               func(string, string, string) error
	Filesystem          func(string) (FilesystemIdentity, error)
	DirectoryIdentity   func(string) (DirectoryIdentity, error)
	PrepareSecurityRoot func(shadowaccount.Record) (string, error)
	CreatePrivateDir    func(string, string, uint32) error
}

func (value Runtime) Validate() error {
	if value.Clone == nil || value.Filesystem == nil || value.DirectoryIdentity == nil ||
		value.PrepareSecurityRoot == nil || value.CreatePrivateDir == nil {
		return errors.New("Shadow workspace runtime is incomplete")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validRootLeaf(value string) bool {
	if !strings.HasPrefix(value, "attempt-") || len(value) != len("attempt-")+32 || filepath.Base(value) != value {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "attempt-") {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func ordinaryDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Shadow workspace path is not an ordinary directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return errors.New("Shadow workspace path contains a symlink")
	}
	return nil
}

func nestedCloneBinding(rootLeaf string, binding contract.ResourceBinding) (contract.ResourceBinding, error) {
	if binding.Kind != "clone_app" || binding.Leaf != cloneLeaf || !validRootLeaf(rootLeaf) {
		return contract.ResourceBinding{}, errors.New("Shadow clone binding is invalid")
	}
	binding.Leaf = filepath.ToSlash(filepath.Join(rootLeaf, cloneLeaf))
	if err := binding.Validate(); err != nil {
		return contract.ResourceBinding{}, err
	}
	return binding, nil
}

func sameBoundDirectory(left, right contract.ResourceBinding) bool {
	return left.Kind == right.Kind && left.Leaf == right.Leaf && left.Device == right.Device &&
		left.Inode == right.Inode && left.UID == right.UID && left.Mode == right.Mode
}

func (value Runtime) Prepare(
	ctx context.Context,
	account shadowaccount.Record,
	sourcePath string,
	rootLeaf string,
	expectedSource DirectoryIdentity,
	expectedInventoryDigest string,
) ([]contract.ResourceBinding, error) {
	if ctx == nil || value.Validate() != nil || account.Validate() != nil ||
		!validRootLeaf(rootLeaf) || !expectedSource.valid() || !validDigest(expectedInventoryDigest) {
		return nil, errors.New("Shadow workspace input is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := shadowaccount.Revalidate(account); err != nil {
		return nil, err
	}
	sourcePath, err := shadowinventory.TrustedRoot(sourcePath)
	if err != nil || filepath.Base(sourcePath) != cloneLeaf {
		return nil, errors.New("Shadow workspace source is invalid")
	}
	sourceBefore, err := value.DirectoryIdentity(sourcePath)
	if err != nil || sourceBefore != expectedSource {
		return nil, errors.New("Shadow workspace source identity drifted before mutation")
	}
	_, sourceDigest, err := shadowinventory.ScanContext(ctx, sourcePath)
	if err != nil || sourceDigest != expectedInventoryDigest {
		return nil, errors.New("Shadow workspace source inventory drifted before mutation")
	}
	sourceAfter, err := value.DirectoryIdentity(sourcePath)
	if err != nil || sourceAfter != sourceBefore {
		return nil, errors.New("Shadow workspace source identity drifted during qualification")
	}
	sourceFilesystem, sourceFSError := value.Filesystem(sourcePath)
	homeFilesystem, homeFSError := value.Filesystem(account.Home)
	if sourceFSError != nil || homeFSError != nil || sourceFilesystem.Device == 0 ||
		sourceFilesystem.Device != homeFilesystem.Device || sourceFilesystem.Type != "apfs" || homeFilesystem.Type != "apfs" {
		return nil, errors.New("Shadow workspace requires same-device APFS clone support")
	}
	securityRoot, err := value.PrepareSecurityRoot(account)
	if err != nil || securityRoot != account.SecurityRoot || ordinaryDirectory(securityRoot) != nil {
		return nil, errors.New("Shadow security root preparation failed")
	}
	securityFilesystem, err := value.Filesystem(securityRoot)
	if err != nil || securityFilesystem != homeFilesystem {
		return nil, errors.New("Shadow security root filesystem drifted")
	}
	workspacePath := filepath.Join(securityRoot, rootLeaf)
	if err := value.CreatePrivateDir(securityRoot, rootLeaf, account.UID); err != nil {
		return nil, errors.New("Shadow workspace cannot be created exclusively")
	}
	workspace, err := shadowcleanup.BindDirectory(securityRoot, rootLeaf, "workspace")
	if err != nil {
		return nil, errors.New("Shadow workspace identity cannot be bound")
	}
	clonePath := filepath.Join(workspacePath, cloneLeaf)
	if err := value.Clone(sourcePath, workspacePath, cloneLeaf); err != nil {
		return nil, errors.New("Shadow APFS clone failed")
	}
	if err := ordinaryDirectory(clonePath); err != nil {
		return nil, err
	}
	cloneBefore, err := shadowcleanup.BindDirectory(workspacePath, cloneLeaf, "clone_app")
	if err != nil {
		return nil, errors.New("Shadow clone identity cannot be bound")
	}
	_, cloneDigest, err := shadowinventory.ScanContext(ctx, clonePath)
	if err != nil || cloneDigest != expectedInventoryDigest {
		return nil, errors.New("Shadow clone content does not bind to the source inventory")
	}
	cloneAfter, err := shadowcleanup.BindDirectory(workspacePath, cloneLeaf, "clone_app")
	workspaceAfter, workspaceErr := shadowcleanup.BindDirectory(securityRoot, rootLeaf, "workspace")
	if err != nil || workspaceErr != nil || cloneAfter != cloneBefore || !sameBoundDirectory(workspaceAfter, workspace) {
		return nil, errors.New("Shadow workspace identity drifted during clone verification")
	}
	workspace = workspaceAfter
	cloneBefore.DigestSHA256 = cloneDigest
	clone, err := nestedCloneBinding(rootLeaf, cloneBefore)
	if err != nil {
		return nil, err
	}
	return []contract.ResourceBinding{workspace, clone}, nil
}

func (value Runtime) Transform(
	ctx context.Context,
	account shadowaccount.Record,
	rootLeaf string,
	buildRoot string,
	manifest shadowtransform.Manifest,
	shadowIdentifier string,
) (shadowtransform.Timings, error) {
	if ctx == nil || account.Validate() != nil || !validRootLeaf(rootLeaf) || value.PrepareSecurityRoot == nil {
		return shadowtransform.Timings{}, errors.New("Shadow transformation workspace input is invalid")
	}
	if err := shadowaccount.Revalidate(account); err != nil {
		return shadowtransform.Timings{}, err
	}
	if err := ordinaryDirectory(account.SecurityRoot); err != nil {
		return shadowtransform.Timings{}, err
	}
	workspacePath := filepath.Join(account.SecurityRoot, rootLeaf)
	if err := ordinaryDirectory(workspacePath); err != nil {
		return shadowtransform.Timings{}, err
	}
	clonePath := filepath.Join(workspacePath, cloneLeaf)
	return (shadowtransform.StaticTransformer{BuildRoot: buildRoot}).Transform(ctx, clonePath, manifest, shadowIdentifier)
}

func RemoveClone(ctx context.Context, account shadowaccount.Record, rootLeaf string, binding contract.ResourceBinding) error {
	if ctx == nil || account.Validate() != nil || !validRootLeaf(rootLeaf) ||
		binding.Kind != "clone_app" || binding.Leaf != filepath.ToSlash(filepath.Join(rootLeaf, cloneLeaf)) {
		return errors.New("Shadow clone removal binding is invalid")
	}
	local := binding
	local.Leaf = cloneLeaf
	return shadowcleanup.RemoveExactDirectory(ctx, filepath.Join(account.SecurityRoot, rootLeaf), local)
}

func RemoveWorkspace(ctx context.Context, account shadowaccount.Record, rootLeaf string, binding contract.ResourceBinding) error {
	if ctx == nil || account.Validate() != nil || !validRootLeaf(rootLeaf) ||
		binding.Kind != "workspace" || binding.Leaf != rootLeaf {
		return errors.New("Shadow workspace removal binding is invalid")
	}
	return shadowcleanup.RemoveExactDirectory(ctx, account.SecurityRoot, binding)
}
