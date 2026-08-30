//go:build darwin

package shadowproduction

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	shadowaccount "github.com/zanescope/v-local-key-provider/internal/shadowaccount"
	shadowbuildset "github.com/zanescope/v-local-key-provider/internal/shadowbuildset"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowinventory "github.com/zanescope/v-local-key-provider/internal/shadowinventory"
	shadowsource "github.com/zanescope/v-local-key-provider/internal/shadowsource"
	shadowtransform "github.com/zanescope/v-local-key-provider/internal/shadowtransform"
	shadowworkspace "github.com/zanescope/v-local-key-provider/internal/shadowworkspace"
)

type cowGateClock struct{ now uint64 }

func (value cowGateClock) NowNS() (uint64, error) { return value.now, nil }

type mutableGateClock struct{ now uint64 }

func (value *mutableGateClock) NowNS() (uint64, error) { return value.now, nil }

type gateLocker struct {
	inner       shadowmodel.Locker
	nilRelease  bool
	failRelease bool
}

func (value gateLocker) Acquire(ctx context.Context) (func() error, error) {
	release, err := value.inner.Acquire(ctx)
	if err != nil || value.nilRelease {
		return nil, err
	}
	return func() error {
		innerErr := release()
		if value.failRelease {
			return errors.Join(innerErr, errors.New("synthetic lock release failure"))
		}
		return innerErr
	}, nil
}

func prelaunchAccount(t *testing.T) shadowaccount.Record {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(home, "Library"), filepath.Join(home, "Library", "Application Support"),
		filepath.Join(home, "Library", "Containers"),
	} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	payload := make([]byte, 20)
	binary.BigEndian.PutUint32(payload[0:4], stat.Uid)
	binary.BigEndian.PutUint64(payload[4:12], uint64(stat.Dev))
	binary.BigEndian.PutUint64(payload[12:20], uint64(stat.Ino))
	digest := sha256.Sum256(append([]byte("v-local-shadow-account/v1\x00"), payload...))
	return shadowaccount.Record{
		UID: stat.Uid, Home: home, HomeDevice: uint64(stat.Dev), HomeInode: uint64(stat.Ino),
		SecurityRoot:   filepath.Join(home, "Library", "Application Support", "v-local", "shadow-runtime"),
		ContainersRoot: filepath.Join(home, "Library", "Containers"), BindingID: hex.EncodeToString(digest[:16]),
	}
}

func prelaunchInspector() shadowsource.Inspector {
	return shadowsource.Inspector{
		VerifyStrict: func(context.Context, string) error { return nil },
		CodeIdentity: func(context.Context, string) (shadowsource.CodeIdentity, error) {
			return shadowsource.CodeIdentity{Identifier: "com.example.source", Team: "TEAM", Requirement: "designated"}, nil
		},
		PlistString: func(_ context.Context, _ string, key string) (string, error) {
			switch key {
			case "CFBundleShortVersionString":
				return "4.1.11", nil
			case "CFBundleVersion":
				return "269136", nil
			default:
				return "com.example.source", nil
			}
		},
		Inventory: shadowinventory.ScanContext,
	}
}

func freezePrelaunchBundle(
	t *testing.T,
	source shadowsource.Manifest,
	transformation shadowtransform.Manifest,
	entitlements []byte,
) Bundle {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sourcePayload, _, err := shadowsource.CanonicalManifest(source)
	if err != nil {
		t.Fatal(err)
	}
	transformationPayload, _, err := shadowtransform.CanonicalManifest(transformation)
	if err != nil {
		t.Fatal(err)
	}
	entitlementDigest := sha256.Sum256(entitlements)
	entitlementLeaf := "shadow-entitlements-" + hex.EncodeToString(entitlementDigest[:]) + ".plist"
	writeArtifact(t, root, "v-local-cli", []byte("cli"), 0o555)
	writeArtifact(t, root, "shadow-contract-v1.json", []byte("{}\n"), 0o444)
	writeArtifact(t, root, "v-local-key-provider", []byte("provider"), 0o555)
	writeArtifact(t, root, "shadow-source-manifest-v1.json", sourcePayload, 0o444)
	writeArtifact(t, root, "v-local-shadow-supervisor", []byte("supervisor"), 0o555)
	writeArtifact(t, root, "shadow-transformation-manifest-v1.json", transformationPayload, 0o444)
	writeArtifact(t, root, entitlementLeaf, entitlements, 0o444)
	artifacts, err := shadowbuildset.InspectArtifacts(root)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := shadowbuildset.Assemble(shadowbuildset.RouteProductionCapable, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := shadowbuildset.Canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, root, shadowbuildset.ManifestLeaf, payload, 0o444)
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	bundle, err := LoadBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestPrelaunchQualifiesCreatesAndRemovesExactWorkspace(t *testing.T) {
	account := prelaunchAccount(t)
	sourcePath := filepath.Join(account.Home, "Fixtures", "WeChat.app")
	for _, path := range []string{
		filepath.Join(sourcePath, "Contents", "Helpers", "Nested.app"),
		filepath.Join(sourcePath, "Contents", "Resources"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "Contents", "Info.plist"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	inspector := prelaunchInspector()
	snapshot, err := inspector.Inspect(context.Background(), sourcePath, []shadowsource.RewriteReference{{
		Path: "Contents/Info.plist", Key: "CFBundleIdentifier",
	}})
	if err != nil {
		t.Fatal(err)
	}
	entitlements := []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>\n")
	entitlementDigest := sha256.Sum256(entitlements)
	entitlementLeaf := "shadow-entitlements-" + hex.EncodeToString(entitlementDigest[:]) + ".plist"
	transformation := shadowtransform.Manifest{
		Version: 1, SourceVersion: snapshot.SourceVersion, SourceBuild: snapshot.SourceBuild,
		SourceInventoryDigest: snapshot.InventoryDigest,
		Rewrites: []shadowtransform.PlistRewrite{{
			Path: "Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "com.example.source",
			Value: shadowtransform.ShadowIdentifierToken,
		}},
		SigningOrder: []shadowtransform.CodeObject{
			{Path: "Contents/Helpers/Nested.app", Role: "nested", Identifier: shadowtransform.ShadowIdentifierToken + ".nested", EntitlementsLeaf: entitlementLeaf},
			{Path: ".", Role: "root", Identifier: shadowtransform.ShadowIdentifierToken, EntitlementsLeaf: entitlementLeaf},
		},
	}
	_, transformationDigest, err := shadowtransform.CanonicalManifest(transformation)
	if err != nil {
		t.Fatal(err)
	}
	sourceManifest, err := shadowsource.Freeze(snapshot, transformationDigest)
	if err != nil {
		t.Fatal(err)
	}
	bundle := freezePrelaunchBundle(t, sourceManifest, transformation, entitlements)
	workspace := shadowworkspace.New()
	prelaunch, err := NewPrelaunch(bundle, account, sourcePath, inspector, workspace, func() string {
		return "sip_enabled_verified"
	})
	if err != nil {
		t.Fatal(err)
	}
	qualification, err := inspector.Qualify(context.Background(), sourcePath, sourceManifest)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.Request{
		Version: contract.Version, Operation: "qualify", RequestID: "0123456789abcdef0123456789abcdef",
		BuildSetDigest: bundle.Digest, SourceQualificationDigest: qualification.QualificationDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: account.BindingID,
		OptionsDigest: "4444444444444444444444444444444444444444444444444444444444444444",
	}
	contractQualification, binding, err := prelaunch.Qualify(context.Background(), request)
	if err != nil || contractQualification.SourceQualificationDigest != qualification.QualificationDigest {
		t.Fatalf("qualification failed: %#v err=%v", contractQualification, err)
	}
	deadline := contract.NewDeadline(1)
	record := shadowmodel.RecoveryRecord{
		Version: 1, Operation: "execute", State: shadowmodel.StatePlanned, AttemptID: request.RequestID,
		ChallengeID: "abcdefabcdefabcdefabcdefabcdefab", BuildSetDigest: bundle.Digest,
		SourceQualificationDigest: qualification.QualificationDigest, CleanupRoute: contract.CleanupRouteDirect,
		AccountBindingID: account.BindingID, OptionsDigest: request.OptionsDigest,
		RootLeaf: "attempt-" + request.RequestID, BundleID: "com.zanescope.vlocal.shadow." + request.RequestID,
		Deadline: deadline, ExpectedSecurityPosture: "sip_enabled_verified", Source: binding,
		PendingAction: shadowmodel.ActionPrepareWorkspace, Resources: []contract.ResourceBinding{},
	}
	resources, err := prelaunch.CreateWorkspace(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	record.Resources = append(record.Resources, resources...)
	if prelaunch.WorkspaceAbsent(record) {
		t.Fatal("workspace was reported absent before cleanup")
	}
	if err := prelaunch.RemoveWorkspace(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if !prelaunch.WorkspaceAbsent(record) || !prelaunch.SourceUnchanged(context.Background(), record) {
		t.Fatal("prelaunch cleanup or source recheck failed")
	}

	runner := QualificationRunner{Prelaunch: prelaunch}
	output, err := runner.Qualify(context.Background(), request)
	if err != nil || output.Result.Status != "qualified" || output.Result.Qualification == nil ||
		output.Result.Qualification.ProductionRouteEnabled {
		t.Fatalf("qualification runner did not remain read-only: %#v err=%v", output.Result, err)
	}
	execute := request
	execute.Operation = "execute"
	execute.ChallengeID = "abcdefabcdefabcdefabcdefabcdefab"
	execute.Deadline = &deadline
	output, err = runner.Execute(context.Background(), execute)
	if err != nil || output.Result.Status != "failed" || output.Result.ErrorCode != contract.ErrorProductionRouteDisabled ||
		len(output.Credential) != 0 {
		t.Fatalf("production execution was not fail-closed: %#v err=%v", output, err)
	}

	mismatch := request
	mismatch.BuildSetDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	output, err = runner.Qualify(context.Background(), mismatch)
	if err != nil || output.Result.ErrorCode != contract.ErrorBuildSetMismatch {
		t.Fatalf("build-set mismatch was not preserved: %#v err=%v", output.Result, err)
	}
	drifted, err := NewPrelaunch(bundle, account, sourcePath, inspector, workspace, func() string {
		return "unknown"
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err = (QualificationRunner{Prelaunch: drifted}).Qualify(context.Background(), request)
	if err != nil || output.Result.ErrorCode != contract.ErrorSecurityPostureDrift {
		t.Fatalf("security posture drift was not preserved: %#v err=%v", output.Result, err)
	}
}

func newGateFixture(t *testing.T) (*Prelaunch, shadowmodel.Journal, shadowmodel.Locker) {
	t.Helper()
	account := prelaunchAccount(t)
	sourcePath := filepath.Join(account.Home, "Fixtures", "WeChat.app")
	if err := os.MkdirAll(filepath.Join(sourcePath, "Contents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "Contents", "Info.plist"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	inspector := prelaunchInspector()
	snapshot, err := inspector.Inspect(context.Background(), sourcePath, []shadowsource.RewriteReference{{
		Path: "Contents/Info.plist", Key: "CFBundleIdentifier",
	}})
	if err != nil {
		t.Fatal(err)
	}
	entitlements := []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>\n")
	digest := sha256.Sum256(entitlements)
	leaf := "shadow-entitlements-" + hex.EncodeToString(digest[:]) + ".plist"
	transformation := shadowtransform.Manifest{
		Version: 1, SourceVersion: snapshot.SourceVersion, SourceBuild: snapshot.SourceBuild,
		SourceInventoryDigest: snapshot.InventoryDigest,
		Rewrites: []shadowtransform.PlistRewrite{{
			Path: "Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "com.example.source",
			Value: shadowtransform.ShadowIdentifierToken,
		}},
		SigningOrder: []shadowtransform.CodeObject{
			{Path: "Contents/Nested.app", Role: "nested", Identifier: shadowtransform.ShadowIdentifierToken + ".nested", EntitlementsLeaf: leaf},
			{Path: ".", Role: "root", Identifier: shadowtransform.ShadowIdentifierToken, EntitlementsLeaf: leaf},
		},
	}
	_, transformationDigest, err := shadowtransform.CanonicalManifest(transformation)
	if err != nil {
		t.Fatal(err)
	}
	sourceManifest, err := shadowsource.Freeze(snapshot, transformationDigest)
	if err != nil {
		t.Fatal(err)
	}
	bundle := freezePrelaunchBundle(t, sourceManifest, transformation, entitlements)
	prelaunch, err := NewPrelaunch(bundle, account, sourcePath, inspector, shadowworkspace.New(), func() string {
		return "sip_enabled_verified"
	})
	if err != nil {
		t.Fatal(err)
	}
	if root, err := prelaunch.Workspace.PrepareSecurityRoot(prelaunch.Account); err != nil || root != account.SecurityRoot {
		t.Fatalf("security root preparation failed: root=%q err=%v", root, err)
	}
	journal, err := shadowmodel.NewFileJournal(account.SecurityRoot)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := shadowmodel.NewFileLocker(account.SecurityRoot)
	if err != nil {
		t.Fatal(err)
	}
	return prelaunch, journal, locker
}

func gateIDs() func() (string, error) {
	ids := []string{"0123456789abcdef0123456789abcdef", "abcdefabcdefabcdefabcdefabcdefab"}
	index := 0
	return func() (string, error) {
		value := ids[index]
		index++
		return value, nil
	}
}

func TestCoWGatePersistsBeforeCloneThenRemovesWorkspaceAndRecovery(t *testing.T) {
	prelaunch, journal, locker := newGateFixture(t)
	summary, err := (CoWGate{
		Prelaunch: prelaunch, Journal: journal, Locker: locker, Clock: cowGateClock{now: 1},
		NewID: gateIDs(),
	}).Run(context.Background())
	if err != nil || summary.Status != "qualified" || !summary.WorkspacePrepared || !summary.CloneAbsent ||
		!summary.WorkspaceAbsent || !summary.RecoveryRecordAbsent || !summary.SourceUnchanged || summary.TransformationApplied {
		t.Fatalf("CoW gate summary=%+v err=%v", summary, err)
	}
}

func TestCoWGateRejectsMissingLockReleaseBeforeMutation(t *testing.T) {
	prelaunch, journal, locker := newGateFixture(t)
	summary, err := (CoWGate{
		Prelaunch: prelaunch, Journal: journal, Locker: gateLocker{inner: locker, nilRelease: true},
		Clock: cowGateClock{now: 1}, NewID: gateIDs(),
	}).Run(context.Background())
	if err == nil || summary.Status != "failed" || summary.WorkspacePrepared {
		t.Fatalf("missing lock release summary=%+v err=%v", summary, err)
	}
	if _, loadErr := journal.Load(); !errors.Is(loadErr, shadowmodel.ErrNoRecoveryRecord) {
		t.Fatalf("missing lock release mutated recovery state: %v", loadErr)
	}
}

func TestCoWGateLockReleaseFailureCannotPublishQualifiedSummary(t *testing.T) {
	prelaunch, journal, locker := newGateFixture(t)
	summary, err := (CoWGate{
		Prelaunch: prelaunch, Journal: journal, Locker: gateLocker{inner: locker, failRelease: true},
		Clock: cowGateClock{now: 1}, NewID: gateIDs(),
	}).Run(context.Background())
	if err == nil || summary.Status != "failed" || !summary.WorkspacePrepared || !summary.WorkspaceAbsent ||
		!summary.RecoveryRecordAbsent || !summary.SourceUnchanged {
		t.Fatalf("failed lock release summary=%+v err=%v", summary, err)
	}
}

func TestTransformationGatePersistsPendingBeforeApplyThenRemovesWorkspaceAndRecovery(t *testing.T) {
	prelaunch, journal, locker := newGateFixture(t)
	applyCalls := 0
	summary, err := (TransformationGate{
		CoWGate: CoWGate{
			Prelaunch: prelaunch, Journal: journal, Locker: locker, Clock: cowGateClock{now: 1},
			NewID: gateIDs(),
		},
		ApplyTransform: func(_ context.Context, record shadowmodel.RecoveryRecord) error {
			applyCalls++
			persisted, loadErr := journal.Load()
			if loadErr != nil {
				return loadErr
			}
			if persisted.AttemptID != record.AttemptID || persisted.State != shadowmodel.StatePrepared ||
				persisted.PendingAction != shadowmodel.ActionTransform {
				return shadowmodel.NewFailure(contract.ErrorTransformationUnsupported)
			}
			clone := filepath.Join(prelaunch.Account.SecurityRoot, record.RootLeaf, "WeChat.app")
			if _, statErr := os.Lstat(clone); statErr != nil {
				return statErr
			}
			return nil
		},
	}).Run(context.Background())
	if err != nil || applyCalls != 1 || summary.Status != "qualified" || !summary.WorkspacePrepared ||
		!summary.TransformationApplied || !summary.CloneAbsent || !summary.WorkspaceAbsent ||
		!summary.RecoveryRecordAbsent || !summary.SourceUnchanged {
		t.Fatalf("transformation gate summary=%+v calls=%d err=%v", summary, applyCalls, err)
	}
}

func TestTransformationGateFailureStillRemovesWorkspaceAndRecovery(t *testing.T) {
	prelaunch, journal, locker := newGateFixture(t)
	applyCalls := 0
	summary, err := (TransformationGate{
		CoWGate: CoWGate{
			Prelaunch: prelaunch, Journal: journal, Locker: locker, Clock: cowGateClock{now: 1},
			NewID: gateIDs(),
		},
		ApplyTransform: func(context.Context, shadowmodel.RecoveryRecord) error {
			applyCalls++
			return context.DeadlineExceeded
		},
	}).Run(context.Background())
	if err == nil || applyCalls != 1 || summary.Status != "failed" || summary.TransformationApplied ||
		!summary.CloneAbsent || !summary.WorkspaceAbsent || !summary.RecoveryRecordAbsent || !summary.SourceUnchanged {
		t.Fatalf("failed transformation gate summary=%+v calls=%d err=%v", summary, applyCalls, err)
	}
}

func TestTransformationGateCallerCancellationCannotCancelCleanup(t *testing.T) {
	prelaunch, journal, locker := newGateFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	summary, err := (TransformationGate{
		CoWGate: CoWGate{
			Prelaunch: prelaunch, Journal: journal, Locker: locker, Clock: cowGateClock{now: 1},
			NewID: gateIDs(),
		},
		ApplyTransform: func(context.Context, shadowmodel.RecoveryRecord) error {
			cancel()
			return context.Canceled
		},
	}).Run(ctx)
	if err == nil || summary.Status != "failed" || summary.TransformationApplied ||
		!summary.CloneAbsent || !summary.WorkspaceAbsent || !summary.RecoveryRecordAbsent || !summary.SourceUnchanged {
		t.Fatalf("cancelled transformation gate summary=%+v err=%v", summary, err)
	}
}

func TestTransformationGateRejectsThirtySecondPreparation(t *testing.T) {
	prelaunch, journal, locker := newGateFixture(t)
	clock := &mutableGateClock{now: 1}
	summary, err := (TransformationGate{
		CoWGate: CoWGate{
			Prelaunch: prelaunch, Journal: journal, Locker: locker, Clock: clock,
			NewID: gateIDs(),
		},
		ApplyTransform: func(context.Context, shadowmodel.RecoveryRecord) error {
			clock.now += contract.TransformationPreparationLimitNS
			return nil
		},
	}).Run(context.Background())
	if err == nil || summary.Status != "failed" || !summary.TransformationApplied ||
		summary.TransformationMS != int64(contract.TransformationPreparationLimitNS/1_000_000) ||
		!summary.CloneAbsent || !summary.WorkspaceAbsent || !summary.RecoveryRecordAbsent || !summary.SourceUnchanged {
		t.Fatalf("late transformation summary=%+v err=%v", summary, err)
	}
}
