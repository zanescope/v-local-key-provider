//go:build darwin

package shadowproduction

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowbuildset "github.com/zanescope/v-local-key-provider/internal/shadowbuildset"
	shadowcleanup "github.com/zanescope/v-local-key-provider/internal/shadowcleanup"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowsource "github.com/zanescope/v-local-key-provider/internal/shadowsource"
	shadowworkspace "github.com/zanescope/v-local-key-provider/internal/shadowworkspace"
)

type Prelaunch struct {
	Bundle          Bundle
	Account         shadowaccount.Record
	SourcePath      string
	Inspector       shadowsource.Inspector
	Workspace       shadowworkspace.Runtime
	SecurityPosture func() string
}

func NewPrelaunch(
	bundle Bundle,
	account shadowaccount.Record,
	sourcePath string,
	inspector shadowsource.Inspector,
	workspace shadowworkspace.Runtime,
	securityPosture func() string,
) (*Prelaunch, error) {
	frozen, frozenErr := LoadBundle(bundle.Root)
	if frozenErr != nil || frozen.Digest != bundle.Digest ||
		frozen.BuildSet.RouteMode != shadowbuildset.RouteProductionCapable ||
		account.Validate() != nil || workspace.Validate() != nil || securityPosture == nil ||
		!filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath || filepath.Base(sourcePath) != "WeChat.app" {
		return nil, errors.New("production prelaunch configuration is invalid")
	}
	bundle = frozen
	return &Prelaunch{
		Bundle: bundle, Account: account, SourcePath: sourcePath, Inspector: inspector,
		Workspace: workspace, SecurityPosture: securityPosture,
	}, nil
}

func sourceBinding(value shadowsource.Qualification) (shadowmodel.SourceBinding, error) {
	snapshot := value.Snapshot
	binding := shadowmodel.SourceBinding{
		Leaf: snapshot.SourceLeaf, Device: snapshot.Identity.Device, Inode: snapshot.Identity.Inode,
		UID: snapshot.Identity.UID, Mode: snapshot.Identity.Mode, ManifestDigest: value.QualificationDigest,
	}
	if binding.Device == 0 || binding.Inode == 0 || binding.Mode == 0 || binding.ManifestDigest == "" {
		return shadowmodel.SourceBinding{}, errors.New("production source binding is incomplete")
	}
	return binding, nil
}

func (value *Prelaunch) qualifyCurrent(ctx context.Context, request contract.Request) (shadowsource.Qualification, shadowmodel.SourceBinding, error) {
	if value == nil || ctx == nil || request.BuildSetDigest != value.Bundle.Digest ||
		request.CleanupRoute != contract.CleanupRouteDirect || request.AccountBindingID != value.Account.BindingID {
		return shadowsource.Qualification{}, shadowmodel.SourceBinding{}, shadowmodel.NewFailure(contract.ErrorBuildSetMismatch)
	}
	if err := shadowaccount.Revalidate(value.Account); err != nil {
		return shadowsource.Qualification{}, shadowmodel.SourceBinding{}, shadowmodel.NewFailure(contract.ErrorSourceDrift)
	}
	if value.SecurityPosture() != "sip_enabled_verified" {
		return shadowsource.Qualification{}, shadowmodel.SourceBinding{}, shadowmodel.NewFailure(contract.ErrorSecurityPostureDrift)
	}
	qualification, err := value.Inspector.Qualify(ctx, value.SourcePath, value.Bundle.Source)
	if err != nil || qualification.QualificationDigest != request.SourceQualificationDigest {
		return shadowsource.Qualification{}, shadowmodel.SourceBinding{}, shadowmodel.NewFailure(contract.ErrorSourceDrift)
	}
	binding, err := sourceBinding(qualification)
	if err != nil {
		return shadowsource.Qualification{}, shadowmodel.SourceBinding{}, shadowmodel.NewFailure(contract.ErrorSourceDrift)
	}
	return qualification, binding, nil
}

func (value *Prelaunch) Qualify(ctx context.Context, request contract.Request) (contract.Qualification, shadowmodel.SourceBinding, error) {
	qualification, binding, err := value.qualifyCurrent(ctx, request)
	if err != nil {
		return contract.Qualification{}, shadowmodel.SourceBinding{}, err
	}
	return contract.Qualification{
		Version: contract.Version, BuildSetDigest: value.Bundle.Digest,
		SourceQualificationDigest: qualification.QualificationDigest, CleanupRoute: contract.CleanupRouteDirect,
		AccountBindingID: value.Account.BindingID, OptionsDigest: request.OptionsDigest,
		SourceVersion: qualification.Snapshot.SourceVersion, SourceBuild: qualification.Snapshot.SourceBuild,
	}, binding, nil
}

func (value *Prelaunch) Requalify(ctx context.Context, request contract.Request) (shadowmodel.SourceBinding, error) {
	_, binding, err := value.qualifyCurrent(ctx, request)
	return binding, err
}

func (value *Prelaunch) CreateWorkspace(ctx context.Context, record shadowmodel.RecoveryRecord) ([]contract.ResourceBinding, error) {
	if value == nil || ctx == nil || ctx.Err() != nil || record.Validate() != nil ||
		record.State != shadowmodel.StatePlanned || record.PendingAction != shadowmodel.ActionPrepareWorkspace ||
		record.BuildSetDigest != value.Bundle.Digest || record.AccountBindingID != value.Account.BindingID ||
		record.Source.ManifestDigest != record.SourceQualificationDigest {
		return nil, shadowmodel.NewFailure(contract.ErrorWorkspacePrepare)
	}
	expectedSource := shadowworkspace.DirectoryIdentity{
		Device: record.Source.Device, Inode: record.Source.Inode, UID: record.Source.UID,
		Mode: record.Source.Mode, LinkCount: value.Bundle.Source.ExpectedLinkCount,
	}
	resources, err := value.Workspace.Prepare(
		ctx, value.Account, value.SourcePath, record.RootLeaf, expectedSource, value.Bundle.Source.InventoryDigest,
	)
	if err != nil {
		return nil, shadowmodel.NewFailure(contract.ErrorWorkspacePrepare)
	}
	return resources, nil
}

func (value *Prelaunch) preparedWorkspaceBound(record shadowmodel.RecoveryRecord) bool {
	if value == nil || record.BuildSetDigest != value.Bundle.Digest ||
		record.AccountBindingID != value.Account.BindingID {
		return false
	}
	expectedWorkspace, workspaceFound := resource(record, "workspace")
	expectedClone, cloneFound := resource(record, "clone_app")
	if !workspaceFound || !cloneFound || expectedWorkspace.Leaf != record.RootLeaf ||
		expectedClone.Leaf != filepath.ToSlash(filepath.Join(record.RootLeaf, "WeChat.app")) ||
		expectedClone.DigestSHA256 != value.Bundle.Source.InventoryDigest {
		return false
	}
	currentWorkspace, err := shadowcleanup.BindDirectory(value.Account.SecurityRoot, record.RootLeaf, "workspace")
	if err != nil || !sameDirectory(currentWorkspace, expectedWorkspace) {
		return false
	}
	workspacePath := filepath.Join(value.Account.SecurityRoot, record.RootLeaf)
	currentClone, err := shadowcleanup.BindDirectory(workspacePath, "WeChat.app", "clone_app")
	if err != nil {
		return false
	}
	currentClone.Leaf = filepath.ToSlash(filepath.Join(record.RootLeaf, "WeChat.app"))
	return sameDirectory(currentClone, expectedClone)
}

func (value *Prelaunch) Transform(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if value == nil || ctx == nil || ctx.Err() != nil || record.Validate() != nil ||
		record.State != shadowmodel.StatePrepared || record.PendingAction != shadowmodel.ActionTransform ||
		record.BundleID != "com.zanescope.vlocal.shadow."+record.AttemptID || !value.preparedWorkspaceBound(record) {
		return shadowmodel.NewFailure(contract.ErrorTransformationUnsupported)
	}
	_, err := value.Workspace.Transform(
		ctx, value.Account, record.RootLeaf, value.Bundle.Root, value.Bundle.Transformation, record.BundleID,
	)
	if err != nil || !value.preparedWorkspaceBound(record) {
		return shadowmodel.NewFailure(contract.ErrorTransformationUnsupported)
	}
	return nil
}

func (value *Prelaunch) SupervisorArtifact(context.Context, shadowmodel.RecoveryRecord) (contract.ResourceBinding, error) {
	binding, err := value.Bundle.SupervisorBinding()
	if err != nil {
		return contract.ResourceBinding{}, shadowmodel.NewFailure(contract.ErrorSupervisor)
	}
	return binding, nil
}

func resource(record shadowmodel.RecoveryRecord, kind string) (contract.ResourceBinding, bool) {
	for _, binding := range record.Resources {
		if binding.Kind == kind {
			return binding, true
		}
	}
	return contract.ResourceBinding{}, false
}

func sameDirectory(left, right contract.ResourceBinding) bool {
	return left.Kind == right.Kind && left.Leaf == right.Leaf && left.Device == right.Device &&
		left.Inode == right.Inode && left.UID == right.UID && left.Mode == right.Mode
}

func (value *Prelaunch) RemoveWorkspace(ctx context.Context, record shadowmodel.RecoveryRecord) error {
	if value == nil || ctx == nil || record.AccountBindingID != value.Account.BindingID {
		return errors.New("production workspace cleanup binding is invalid")
	}
	workspacePath := filepath.Join(value.Account.SecurityRoot, record.RootLeaf)
	clonePath := filepath.Join(workspacePath, "WeChat.app")
	if _, err := os.Lstat(clonePath); err == nil {
		current, bindErr := shadowcleanup.BindDirectory(workspacePath, "WeChat.app", "clone_app")
		if bindErr != nil {
			return bindErr
		}
		current.Leaf = filepath.ToSlash(filepath.Join(record.RootLeaf, "WeChat.app"))
		if expected, found := resource(record, "clone_app"); found && !sameDirectory(current, expected) {
			return errors.New("production clone cleanup identity drifted")
		}
		if err := shadowworkspace.RemoveClone(ctx, value.Account, record.RootLeaf, current); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(workspacePath); err == nil {
		current, bindErr := shadowcleanup.BindDirectory(value.Account.SecurityRoot, record.RootLeaf, "workspace")
		if bindErr != nil {
			return bindErr
		}
		if expected, found := resource(record, "workspace"); found && !sameDirectory(current, expected) {
			return errors.New("production workspace cleanup identity drifted")
		}
		return shadowworkspace.RemoveWorkspace(ctx, value.Account, record.RootLeaf, current)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (value *Prelaunch) WorkspaceAbsent(record shadowmodel.RecoveryRecord) bool {
	if value == nil || record.AccountBindingID != value.Account.BindingID {
		return false
	}
	_, err := os.Lstat(filepath.Join(value.Account.SecurityRoot, record.RootLeaf))
	return os.IsNotExist(err)
}

func (value *Prelaunch) CloneAbsent(record shadowmodel.RecoveryRecord) bool {
	if value == nil || record.AccountBindingID != value.Account.BindingID {
		return false
	}
	_, err := os.Lstat(filepath.Join(value.Account.SecurityRoot, record.RootLeaf, "WeChat.app"))
	return os.IsNotExist(err)
}

func (value *Prelaunch) SourceUnchanged(ctx context.Context, record shadowmodel.RecoveryRecord) bool {
	request := contract.Request{
		Version: contract.Version, Operation: "execute", RequestID: record.AttemptID,
		ChallengeID: record.ChallengeID, BuildSetDigest: record.BuildSetDigest,
		SourceQualificationDigest: record.SourceQualificationDigest, CleanupRoute: record.CleanupRoute,
		AccountBindingID: record.AccountBindingID, OptionsDigest: record.OptionsDigest, Deadline: &record.Deadline,
	}
	binding, err := value.Requalify(ctx, request)
	return err == nil && binding == record.Source
}
