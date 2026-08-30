//go:build darwin

package shadowtransform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryFreezesDeepestFirstTemplatesAndLeavesSourceUnchanged(t *testing.T) {
	base := canonicalTestRoot(t)
	source, _ := buildSignedFixture(t, base)
	_, inventoryBefore, err := Inventory(source)
	if err != nil {
		t.Fatal(err)
	}
	input := DiscoveryInput{
		SourceVersion: "4.1.11", SourceBuild: "26000", SourceInventoryDigest: inventoryBefore,
		RewriteInputs: []PlistRewrite{
			{Path: "Contents/Helpers/Nested.app/Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "com.zanescope.synthetic.helper"},
			{Path: "Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "com.zanescope.synthetic.source"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := Discover(ctx, source, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Manifest.SigningOrder) != 2 || result.Manifest.SigningOrder[0].Path != "Contents/Helpers/Nested.app" ||
		result.Manifest.SigningOrder[1].Path != "." || result.Manifest.SigningOrder[1].Identifier != ShadowIdentifierToken {
		t.Fatalf("discovery signing plan is not deterministic deepest-first: %+v", result.Manifest.SigningOrder)
	}
	for _, rewrite := range result.Manifest.Rewrites {
		if !validIdentifierTemplate(rewrite.Value) || strings.Contains(rewrite.Value, "abcdef") {
			t.Fatalf("discovery froze a per-attempt identity: %+v", rewrite)
		}
	}
	for _, profile := range result.Profiles {
		sum := sha256.Sum256(profile.Payload)
		if !strings.Contains(profile.Leaf, hex.EncodeToString(sum[:])) || bytes.Contains(profile.Payload, []byte(source)) {
			t.Fatalf("entitlement profile is not content-addressed and path-free: %s", profile.Leaf)
		}
	}
	_, inventoryAfter, err := Inventory(source)
	if err != nil || inventoryAfter != inventoryBefore {
		t.Fatalf("discovery changed the signed source: before=%s after=%s err=%v", inventoryBefore, inventoryAfter, err)
	}
}

func TestEntitlementSanitizerRemovesOriginalTeamAndContainerBindings(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.application-identifier</key><string>5A4RE8SF68.com.tencent.xinWeChat</string>
<key>com.apple.developer.team-identifier</key><string>5A4RE8SF68</string>
<key>com.apple.security.application-groups</key><array><string>group.com.tencent.xinWeChat</string></array>
<key>com.apple.security.network.client</key><true/>
</dict></plist>`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := canonicalEntitlements(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(result, []byte("5A4RE8SF68")) || bytes.Contains(result, []byte("com.tencent")) ||
		!bytes.Contains(result, []byte("com.apple.security.network.client")) {
		t.Fatalf("sanitized entitlement profile retained identity or lost a functional key: %s", result)
	}
}

func TestManifestRejectsFixedPerAttemptIdentifiers(t *testing.T) {
	manifest := Manifest{
		Version: ManifestVersion, SourceVersion: "1", SourceBuild: "1",
		SourceInventoryDigest: strings.Repeat("1", 64),
		Rewrites: []PlistRewrite{{
			Path: "Contents/Info.plist", Key: "CFBundleIdentifier", Expected: "source",
			Value: "com.zanescope.vlocal.shadow.abcdefabcdefabcdefabcdefabcdefab",
		}},
		SigningOrder: []CodeObject{
			{Path: "Contents/Nested.app", Role: "nested", Identifier: ShadowIdentifierToken + ".nested", EntitlementsLeaf: "nested.plist"},
			{Path: ".", Role: "root", Identifier: ShadowIdentifierToken, EntitlementsLeaf: "root.plist"},
		},
	}
	if err := manifest.Validate(); err == nil {
		t.Fatal("transformation manifest accepted a frozen per-attempt identifier")
	}
}
