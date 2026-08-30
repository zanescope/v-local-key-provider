//go:build darwin

package shadowproduction

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	shadowbuildset "github.com/zanescope/v-local-key-provider/internal/shadowbuildset"
	shadowsource "github.com/zanescope/v-local-key-provider/internal/shadowsource"
	shadowtransform "github.com/zanescope/v-local-key-provider/internal/shadowtransform"
)

func writeArtifact(t *testing.T, root, leaf string, payload []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, leaf), payload, mode); err != nil {
		t.Fatal(err)
	}
}

func productionBundleFixture(t *testing.T) (string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	entitlements := []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>\n")
	entitlementDigest := sha256.Sum256(entitlements)
	entitlementHex := hex.EncodeToString(entitlementDigest[:])
	entitlementLeaf := "shadow-entitlements-" + entitlementHex + ".plist"
	transformation := shadowtransform.Manifest{
		Version: 1, SourceVersion: "4.1.11", SourceBuild: "269136",
		SourceInventoryDigest: "1111111111111111111111111111111111111111111111111111111111111111",
		Rewrites: []shadowtransform.PlistRewrite{{
			Path: "Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "com.example.source",
			Value: shadowtransform.ShadowIdentifierToken,
		}},
		SigningOrder: []shadowtransform.CodeObject{
			{Path: "Contents/Helpers/Nested.app", Role: "nested", Identifier: shadowtransform.ShadowIdentifierToken + ".nested", EntitlementsLeaf: entitlementLeaf},
			{Path: ".", Role: "root", Identifier: shadowtransform.ShadowIdentifierToken, EntitlementsLeaf: entitlementLeaf},
		},
	}
	transformationPayload, transformationDigest, err := shadowtransform.CanonicalManifest(transformation)
	if err != nil {
		t.Fatal(err)
	}
	source := shadowsource.Manifest{
		Version: 1, SourceLeaf: "WeChat.app",
		SourcePathDigest: "2222222222222222222222222222222222222222222222222222222222222222",
		SourceVersion:    "4.1.11", SourceBuild: "269136", RootIdentifier: "com.example.source", TeamIdentifier: "TEAM",
		RequirementDigest: "3333333333333333333333333333333333333333333333333333333333333333",
		InventoryDigest:   transformation.SourceInventoryDigest, InventoryEntries: 3, ExpectedUID: 0, ExpectedMode: 0o755,
		ExpectedLinkCount: 3, TransformationManifestDigest: transformationDigest,
		RewriteInputs: []shadowsource.RewriteInput{{Path: "Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "com.example.source"}},
	}
	sourcePayload, _, err := shadowsource.CanonicalManifest(source)
	if err != nil {
		t.Fatal(err)
	}
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
	payload, digest, err := shadowbuildset.Canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, root, shadowbuildset.ManifestLeaf, payload, 0o444)
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	return root, digest
}

func TestLoadBundleRequiresCrossBoundProductionArtifacts(t *testing.T) {
	root, expectedDigest := productionBundleFixture(t)
	bundle, err := LoadBundle(root)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Digest != expectedDigest || bundle.BuildSet.RouteMode != shadowbuildset.RouteProductionCapable ||
		bundle.Source.TransformationManifestDigest != bundle.BuildSet.TransformationManifestDigest {
		t.Fatalf("unexpected production bundle: %#v", bundle)
	}
	if binding, err := bundle.SupervisorBinding(); err != nil || binding.DigestSHA256 == "" || binding.Leaf != "v-local-shadow-supervisor" {
		t.Fatalf("unexpected supervisor binding: %#v err=%v", binding, err)
	}
}
