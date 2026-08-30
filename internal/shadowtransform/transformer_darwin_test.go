//go:build darwin

package shadowtransform

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const rootInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.zanescope.synthetic.source</string>
<key>CFBundleExecutable</key><string>SyntheticMain</string>
<key>CFBundleVersion</key><string>26000</string>
<key>CFBundleShortVersionString</key><string>4.1.11</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
`

const nestedInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.zanescope.synthetic.helper</string>
<key>CFBundleExecutable</key><string>Nested</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
`

const rootEntitlements = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
`

const nestedEntitlements = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>
`

func canonicalTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func copyExecutable(t *testing.T, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
}

func requirePlatformTools(t *testing.T) {
	t.Helper()
	for _, path := range []string{"/usr/bin/codesign", "/usr/bin/plutil", "/usr/bin/true"} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("required macOS tool missing: %s", path)
		}
	}
}

func buildSignedFixture(t *testing.T, base string) (string, string) {
	t.Helper()
	requirePlatformTools(t)
	app := filepath.Join(base, "Source.app")
	build := filepath.Join(base, "build-set")
	writeTestFile(t, filepath.Join(app, "Contents", "Info.plist"), rootInfoPlist, 0o600)
	copyExecutable(t, filepath.Join(app, "Contents", "MacOS", "SyntheticMain"))
	writeTestFile(t, filepath.Join(app, "Contents", "Helpers", "Nested.app", "Contents", "Info.plist"), nestedInfoPlist, 0o600)
	copyExecutable(t, filepath.Join(app, "Contents", "Helpers", "Nested.app", "Contents", "MacOS", "Nested"))
	writeTestFile(t, filepath.Join(app, "Contents", "Resources", "keep.txt"), "keep", 0o600)
	writeTestFile(t, filepath.Join(app, "Contents", "Resources", "remove.me"), "remove", 0o600)
	if err := os.Symlink("keep.txt", filepath.Join(app, "Contents", "Resources", "keep.link")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(build, "root.entitlements"), rootEntitlements, 0o600)
	writeTestFile(t, filepath.Join(build, "nested.entitlements"), nestedEntitlements, 0o600)
	runner := ExecRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nested := filepath.Join(app, "Contents", "Helpers", "Nested.app")
	if err := runner.Run(ctx, "/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "com.zanescope.synthetic.helper",
		"--entitlements", filepath.Join(build, "nested.entitlements"), nested); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx, "/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "com.zanescope.synthetic.source",
		"--entitlements", filepath.Join(build, "root.entitlements"), app); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app); err != nil {
		t.Fatal(err)
	}
	return app, build
}

func cloneFixture(t *testing.T, source, target string) {
	t.Helper()
	if err := unix.Clonefile(source, target, unix.CLONE_NOFOLLOW); err != nil {
		t.Skipf("APFS synthetic clonefile unavailable: %v", err)
	}
}

func transformationManifest(t *testing.T, source string) Manifest {
	t.Helper()
	_, digest, err := Inventory(source)
	if err != nil {
		t.Fatal(err)
	}
	return Manifest{
		Version: ManifestVersion, SourceVersion: "4.1.11", SourceBuild: "26000", SourceInventoryDigest: digest,
		Removals: []Removal{{Path: "Contents/Resources/remove.me", Type: "file"}},
		Rewrites: []PlistRewrite{
			{Path: "Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "com.zanescope.synthetic.source", Value: ShadowIdentifierToken},
			{Path: "Contents/Helpers/Nested.app/Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "com.zanescope.synthetic.helper", Value: ShadowIdentifierToken + ".helper"},
		},
		SigningOrder: []CodeObject{
			{Path: "Contents/Helpers/Nested.app", Role: "nested_helper", Identifier: ShadowIdentifierToken + ".helper", EntitlementsLeaf: "nested.entitlements"},
			{Path: ".", Role: "root_app", Identifier: ShadowIdentifierToken, EntitlementsLeaf: "root.entitlements"},
		},
	}
}

func TestSyntheticNestedCodeReproducesStaleSealThenDeepestFirstPassesStrict(t *testing.T) {
	base := canonicalTestRoot(t)
	source, build := buildSignedFixture(t, base)
	manifest := transformationManifest(t, source)
	sourceInfo, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	_, sourceDigestBefore, err := Inventory(source)
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(base, "Stale.app")
	cloneFixture(t, source, stale)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runner := ExecRunner{}
	if err := runner.Run(ctx, "/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "com.zanescope.synthetic.changed",
		"--entitlements", filepath.Join(build, "nested.entitlements"), filepath.Join(stale, "Contents", "Helpers", "Nested.app")); err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", stale); err == nil {
		t.Fatal("nested re-sign did not reproduce the stale parent seal failure")
	}
	target := filepath.Join(base, "Shadow.app")
	cloneFixture(t, source, target)
	timings, err := (StaticTransformer{BuildRoot: build, Runner: runner}).Transform(ctx, target, manifest, "com.zanescope.vlocal.shadow.abcdefabcdefabcdefabcdefabcdefab")
	if err != nil {
		t.Fatal(err)
	}
	if timings.Total <= 0 || timings.Total >= 30*time.Second {
		t.Fatalf("synthetic transformation duration violates the hard threshold: %s", timings.Total)
	}
	if _, err := os.Lstat(filepath.Join(target, "Contents", "Resources", "remove.me")); !os.IsNotExist(err) {
		t.Fatalf("static removal was not exact: %v", err)
	}
	identifier, err := runner.Output(ctx, "/usr/bin/plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", filepath.Join(target, "Contents", "Info.plist"))
	if err != nil || identifier != "com.zanescope.vlocal.shadow.abcdefabcdefabcdefabcdefabcdefab" {
		t.Fatalf("root identity rewrite failed: %q err=%v", identifier, err)
	}
	sourceInfoAfter, err := os.Stat(source)
	if err != nil || !os.SameFile(sourceInfo, sourceInfoAfter) {
		t.Fatal("synthetic source identity changed")
	}
	_, sourceDigestAfter, err := Inventory(source)
	if err != nil || sourceDigestAfter != sourceDigestBefore {
		t.Fatalf("synthetic source content changed: before=%s after=%s err=%v", sourceDigestBefore, sourceDigestAfter, err)
	}
}

func TestStaticTransformerRejectsInventoryDriftBeforeMutation(t *testing.T) {
	base := canonicalTestRoot(t)
	source, build := buildSignedFixture(t, base)
	manifest := transformationManifest(t, source)
	target := filepath.Join(base, "Drift.app")
	cloneFixture(t, source, target)
	writeTestFile(t, filepath.Join(target, "Contents", "Resources", "keep.txt"), "drift", 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := (StaticTransformer{BuildRoot: build}).Transform(ctx, target, manifest, "com.zanescope.vlocal.shadow.abcdefabcdefabcdefabcdefabcdefab"); err == nil {
		t.Fatal("inventory drift reached static mutation")
	}
	if _, err := os.Stat(filepath.Join(target, "Contents", "Resources", "remove.me")); err != nil {
		t.Fatal("drift failure mutated the removal target")
	}
	identifier, err := (ExecRunner{}).Output(ctx, "/usr/bin/plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-", filepath.Join(target, "Contents", "Info.plist"))
	if err != nil || identifier != "com.zanescope.synthetic.source" {
		t.Fatal("drift failure rewrote Info.plist")
	}
}

func TestManifestRejectsRootBeforeNestedCode(t *testing.T) {
	manifest := Manifest{
		Version: ManifestVersion, SourceVersion: "1", SourceBuild: "1",
		SourceInventoryDigest: "1111111111111111111111111111111111111111111111111111111111111111",
		SigningOrder: []CodeObject{
			{Path: ".", Role: "root", Identifier: ShadowIdentifierToken, EntitlementsLeaf: "root.plist"},
			{Path: "Contents/Helpers/Nested.app", Role: "nested", Identifier: ShadowIdentifierToken + ".nested", EntitlementsLeaf: "nested.plist"},
		},
	}
	if err := manifest.Validate(); err == nil {
		t.Fatal("root-before-nested signing plan was accepted")
	}
}

func TestInventoryRejectsSymlinkThatEscapesAppRoot(t *testing.T) {
	base := canonicalTestRoot(t)
	root := filepath.Join(base, "Unsafe.app")
	outside := filepath.Join(base, "outside.txt")
	writeTestFile(t, outside, "outside", 0o600)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside.txt", filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Inventory(root); err == nil {
		t.Fatal("inventory accepted an app symlink that resolves outside its root")
	}
}

func TestExactTargetRejectsIntermediateSymlink(t *testing.T) {
	base := canonicalTestRoot(t)
	root := filepath.Join(base, "Target.app")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "Contents")); err != nil {
		t.Fatal(err)
	}
	if _, err := exactTarget(root, "Contents/Info.plist", false); err == nil {
		t.Fatal("static target accepted an intermediate symlink")
	}
}
