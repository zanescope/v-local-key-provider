//go:build darwin

package shadowtransform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	shadowinventory "github.com/zanescope/v-local-key-provider/internal/shadowinventory"
)

const (
	maxDiscoveryOutput  = 1024 * 1024
	derEntitlementMagic = uint32(0xfade7172)
	xmlEntitlementMagic = uint32(0xfade7171)
)

var strippedEntitlementKeys = []string{
	"com.apple.application-identifier",
	"com.apple.developer.icloud-container-identifiers",
	"com.apple.developer.team-identifier",
	"com.apple.developer.ubiquity-container-identifiers",
	"com.apple.security.application-groups",
	"keychain-access-groups",
}

const emptyEntitlements = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict/></plist>
`

type discoveryCandidate struct {
	Path       string
	Target     string
	Executable string
	Role       string
}

type boundedDiscoveryBuffer struct {
	payload  []byte
	limit    int
	overflow bool
}

func (value *boundedDiscoveryBuffer) Write(payload []byte) (int, error) {
	remaining := value.limit - len(value.payload)
	if remaining > 0 {
		if remaining > len(payload) {
			remaining = len(payload)
		}
		value.payload = append(value.payload, payload[:remaining]...)
	}
	if remaining < len(payload) {
		value.overflow = true
	}
	return len(payload), nil
}

func discoveryCommand(ctx context.Context, input []byte, combined bool, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	stdout := &boundedDiscoveryBuffer{limit: maxDiscoveryOutput}
	stderr := &boundedDiscoveryBuffer{limit: 32 * 1024}
	command.Stdout = stdout
	if combined {
		command.Stderr = stdout
	} else {
		command.Stderr = stderr
	}
	if err := command.Run(); err != nil || stdout.overflow || stderr.overflow {
		return stdout.payload, errors.New("bounded Shadow discovery command failed")
	}
	return stdout.payload, nil
}

func verifyStrictSource(ctx context.Context, root string) error {
	_, err := discoveryCommand(ctx, nil, true, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", root)
	return err
}

func signedExecutable(ctx context.Context, root, target string) (string, error) {
	output, err := discoveryCommand(ctx, nil, true, "/usr/bin/codesign", "-d", "--verbose=4", target)
	if err != nil {
		return "", err
	}
	executable := ""
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "Executable=") {
			executable = strings.TrimSpace(strings.TrimPrefix(line, "Executable="))
			break
		}
	}
	if executable == "" {
		return "", errors.New("signed Shadow candidate lacks an executable binding")
	}
	executable, err = filepath.EvalSymlinks(filepath.Clean(executable))
	if err != nil || !shadowinventory.WithinRoot(root, executable) {
		return "", errors.New("signed Shadow candidate executable escaped the source")
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("signed Shadow candidate executable is invalid")
	}
	return executable, nil
}

func isCodeBundle(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".app", ".appex", ".xpc", ".framework", ".bundle", ".plugin":
		return true
	}
	return false
}

func candidateRole(path string) string {
	if path == "." {
		return "root_app"
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".app":
		return "nested_app"
	case ".appex":
		return "app_extension"
	case ".xpc":
		return "xpc_service"
	case ".framework":
		return "framework"
	case ".bundle":
		return "bundle"
	case ".plugin":
		return "plugin"
	default:
		return "mach_o"
	}
}

func isMachO(path string) bool {
	if value, err := macho.OpenFat(path); err == nil {
		_ = value.Close()
		return true
	}
	value, err := macho.Open(path)
	if err != nil {
		return false
	}
	_ = value.Close()
	return true
}

func discoverCandidates(ctx context.Context, root string) ([]discoveryCandidate, error) {
	rootExecutable, err := signedExecutable(ctx, root, root)
	if err != nil {
		return nil, err
	}
	bundles := []discoveryCandidate{{Path: ".", Target: root, Executable: rootExecutable, Role: "root_app"}}
	machOFiles := []string{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() && isCodeBundle(path) {
			executable, candidateErr := signedExecutable(ctx, root, path)
			if candidateErr == nil {
				relative, relativeErr := filepath.Rel(root, path)
				if relativeErr != nil || !safeRelative(relative, false) {
					return errors.New("signed Shadow bundle path is invalid")
				}
				bundles = append(bundles, discoveryCandidate{
					Path: filepath.ToSlash(relative), Target: path, Executable: executable, Role: candidateRole(path),
				})
			}
			return nil
		}
		if entry.Type().IsRegular() && isMachO(path) {
			machOFiles = append(machOFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	mainExecutables := map[string]bool{}
	for _, candidate := range bundles {
		mainExecutables[candidate.Executable] = true
	}
	result := append([]discoveryCandidate(nil), bundles...)
	for _, path := range machOFiles {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || mainExecutables[resolved] {
			continue
		}
		executable, err := signedExecutable(ctx, root, path)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || !safeRelative(relative, false) {
			return nil, errors.New("signed Shadow Mach-O path is invalid")
		}
		result = append(result, discoveryCandidate{
			Path: filepath.ToSlash(relative), Target: path, Executable: executable, Role: "mach_o",
		})
	}
	seen := map[string]bool{}
	for _, candidate := range result {
		if seen[candidate.Path] {
			return nil, errors.New("signed Shadow code object is duplicated")
		}
		seen[candidate.Path] = true
	}
	return result, nil
}

func plistKeyPath(value string) string { return strings.ReplaceAll(value, ".", `\.`) }

func plistHasKey(ctx context.Context, payload []byte, key string) bool {
	_, err := discoveryCommand(ctx, payload, false, "/usr/bin/plutil", "-type", plistKeyPath(key), "--", "-")
	return err == nil
}

func canonicalEntitlements(ctx context.Context, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		payload = []byte(emptyEntitlements)
	}
	converted, err := discoveryCommand(ctx, payload, false, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", "--", "-")
	if err != nil {
		return nil, errors.New("Shadow entitlement profile is not a property list")
	}
	for _, key := range strippedEntitlementKeys {
		if !plistHasKey(ctx, converted, key) {
			continue
		}
		converted, err = discoveryCommand(ctx, converted, false, "/usr/bin/plutil", "-remove", plistKeyPath(key), "-o", "-", "--", "-")
		if err != nil {
			return nil, errors.New("Shadow entitlement identity could not be stripped")
		}
	}
	converted, err = discoveryCommand(ctx, converted, false, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", "--", "-")
	if err != nil || bytes.Contains(converted, []byte("com.tencent")) || bytes.Contains(converted, []byte("5A4RE8SF68")) {
		return nil, errors.New("Shadow entitlement profile retains the original application identity")
	}
	return converted, nil
}

func extractEntitlements(ctx context.Context, executable string) ([]byte, error) {
	blob, err := discoveryCommand(ctx, nil, false, "/usr/bin/derq", "macho", "-i", executable)
	if err != nil {
		blob, err = discoveryCommand(ctx, nil, false, "/usr/bin/derq", "macho", "--xml", "-i", executable)
		if err == nil {
			if len(blob) < 8 || binary.BigEndian.Uint32(blob[:4]) != xmlEntitlementMagic ||
				int(binary.BigEndian.Uint32(blob[4:8])) != len(blob) {
				return nil, errors.New("Shadow XML entitlement binding is invalid")
			}
			return canonicalEntitlements(ctx, blob[8:])
		}
		probe, probeErr := discoveryCommand(ctx, nil, false, "/usr/bin/codesign", "-d", "--der", "--entitlements", "-", executable)
		if probeErr == nil && len(probe) == 0 {
			return canonicalEntitlements(ctx, nil)
		}
		return nil, errors.New("Shadow entitlement extraction failed")
	}
	if len(blob) == 0 {
		return canonicalEntitlements(ctx, nil)
	}
	if len(blob) < 8 || int(binary.BigEndian.Uint32(blob[4:8])) != len(blob) {
		return nil, errors.New("Shadow DER entitlement binding is invalid")
	}
	switch binary.BigEndian.Uint32(blob[:4]) {
	case xmlEntitlementMagic:
		return canonicalEntitlements(ctx, blob[8:])
	case derEntitlementMagic:
		xml, err := discoveryCommand(ctx, blob[8:], false, "/usr/bin/derq", "query", "--xml")
		if err != nil {
			return nil, errors.New("Shadow DER entitlements cannot be converted")
		}
		return canonicalEntitlements(ctx, xml)
	default:
		return nil, errors.New("Shadow entitlement blob has an unsupported magic")
	}
}

func shortPathDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}

func rewriteObjectPath(value string) (string, error) {
	const suffix = "/Contents/Info.plist"
	if value == "Contents/Info.plist" {
		return ".", nil
	}
	if !strings.HasSuffix(value, suffix) {
		return "", errors.New("Shadow rewrite input does not identify a code bundle")
	}
	result := strings.TrimSuffix(value, suffix)
	if !safeRelative(filepath.FromSlash(result), false) {
		return "", errors.New("Shadow rewrite bundle path is invalid")
	}
	return result, nil
}

func Discover(ctx context.Context, sourceRoot string, input DiscoveryInput) (Discovery, error) {
	if ctx == nil || input.validate() != nil {
		return Discovery{}, errors.New("Shadow discovery input is invalid")
	}
	root, err := trustedRoot(sourceRoot)
	if err != nil || verifyStrictSource(ctx, root) != nil {
		return Discovery{}, errors.New("Shadow discovery source is not strictly verified")
	}
	_, inventoryBefore, err := Inventory(root)
	if err != nil || inventoryBefore != input.SourceInventoryDigest {
		return Discovery{}, errors.New("Shadow discovery source inventory drifted")
	}
	candidates, err := discoverCandidates(ctx, root)
	if err != nil || len(candidates) < 2 || len(candidates) > maxSigningObjects {
		return Discovery{}, errors.New("Shadow discovery code-object set is invalid")
	}
	candidateByPath := map[string]discoveryCandidate{}
	for _, candidate := range candidates {
		candidateByPath[candidate.Path] = candidate
	}
	templates := map[string]string{}
	rewrites := make([]PlistRewrite, len(input.RewriteInputs))
	for index, rewrite := range input.RewriteInputs {
		objectPath, err := rewriteObjectPath(rewrite.Path)
		if err != nil || candidateByPath[objectPath].Path == "" && objectPath != "." {
			return Discovery{}, errors.New("Shadow rewrite input does not bind a signed code object")
		}
		template := ShadowIdentifierToken
		if objectPath != "." {
			template += ".bundle." + shortPathDigest(objectPath)
		}
		templates[objectPath] = template
		rewrites[index] = PlistRewrite{Path: rewrite.Path, Key: rewrite.Key, Expected: rewrite.Expected, Value: template}
	}
	profilesByLeaf := map[string][]byte{}
	objects := make([]CodeObject, 0, len(candidates))
	seenIdentifiers := map[string]bool{}
	for _, candidate := range candidates {
		identifier := templates[candidate.Path]
		if identifier == "" {
			identifier = ShadowIdentifierToken + ".code." + shortPathDigest(candidate.Path)
		}
		if seenIdentifiers[identifier] {
			return Discovery{}, errors.New("Shadow discovery identifier template collided")
		}
		seenIdentifiers[identifier] = true
		profile, err := extractEntitlements(ctx, candidate.Executable)
		if err != nil {
			return Discovery{}, fmt.Errorf("Shadow entitlement extraction failed for %q: %w", candidate.Path, err)
		}
		sum := sha256.Sum256(profile)
		profileLeaf := "shadow-entitlements-" + hex.EncodeToString(sum[:]) + ".plist"
		if existing, found := profilesByLeaf[profileLeaf]; found && !bytes.Equal(existing, profile) {
			return Discovery{}, errors.New("Shadow entitlement profile digest collided")
		}
		profilesByLeaf[profileLeaf] = profile
		objects = append(objects, CodeObject{
			Path: candidate.Path, Role: candidate.Role, Identifier: identifier, EntitlementsLeaf: profileLeaf,
		})
	}
	sort.Slice(objects, func(left, right int) bool {
		leftDepth, rightDepth := pathDepth(objects[left].Path), pathDepth(objects[right].Path)
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return objects[left].Path < objects[right].Path
	})
	manifest := Manifest{
		Version: ManifestVersion, SourceVersion: input.SourceVersion, SourceBuild: input.SourceBuild,
		SourceInventoryDigest: input.SourceInventoryDigest, Removals: []Removal{}, Rewrites: rewrites,
		SigningOrder: objects,
	}
	if err := manifest.Validate(); err != nil {
		return Discovery{}, err
	}
	profiles := make([]EntitlementProfile, 0, len(profilesByLeaf))
	for leaf, payload := range profilesByLeaf {
		profiles = append(profiles, EntitlementProfile{Leaf: leaf, Payload: payload})
	}
	sortProfiles(profiles)
	_, inventoryAfter, err := Inventory(root)
	if err != nil || inventoryAfter != inventoryBefore || verifyStrictSource(ctx, root) != nil {
		return Discovery{}, errors.New("Shadow discovery source drifted during inspection")
	}
	result := Discovery{Manifest: manifest, Profiles: profiles}
	if err := result.Validate(); err != nil {
		return Discovery{}, err
	}
	return result, nil
}
