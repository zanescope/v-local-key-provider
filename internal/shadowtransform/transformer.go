package shadowtransform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	shadowinventory "github.com/zanescope/v-local-key-provider/internal/shadowinventory"
)

const (
	ManifestVersion       = 1
	ShadowIdentifierToken = "{{shadow_bundle_id}}"
	shadowIdentifierBase  = "com.zanescope.vlocal.shadow."
	maxSigningObjects     = 512
)

type Removal struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type PlistRewrite struct {
	Path     string `json:"path"`
	Key      string `json:"key"`
	Expected string `json:"expected"`
	Value    string `json:"value"`
}

type CodeObject struct {
	Path             string `json:"path"`
	Role             string `json:"role"`
	Identifier       string `json:"identifier"`
	EntitlementsLeaf string `json:"entitlements_leaf"`
}

type Manifest struct {
	Version               int            `json:"version"`
	SourceVersion         string         `json:"source_version"`
	SourceBuild           string         `json:"source_build"`
	SourceInventoryDigest string         `json:"source_inventory_digest"`
	Removals              []Removal      `json:"removals"`
	Rewrites              []PlistRewrite `json:"rewrites"`
	SigningOrder          []CodeObject   `json:"signing_order"`
}

func safeRelative(path string, allowRoot bool) bool {
	if path == "." && allowRoot {
		return true
	}
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") || filepath.Clean(path) != path {
		return false
	}
	return path != ".." && !strings.HasPrefix(path, ".."+string(filepath.Separator))
}

func pathDepth(path string) int {
	if path == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(path), "/") + 1
}

func validIdentifierTemplate(value string) bool {
	if strings.Count(value, ShadowIdentifierToken) != 1 || !strings.HasPrefix(value, ShadowIdentifierToken) {
		return false
	}
	suffix := strings.TrimPrefix(value, ShadowIdentifierToken)
	if suffix == "" {
		return true
	}
	if !strings.HasPrefix(suffix, ".") || strings.HasSuffix(suffix, ".") || strings.Contains(suffix, "..") {
		return false
	}
	for _, character := range strings.TrimPrefix(suffix, ".") {
		if character != '.' && character != '-' && character != '_' &&
			(character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validShadowIdentifier(value string) bool {
	if !strings.HasPrefix(value, shadowIdentifierBase) {
		return false
	}
	suffix := strings.TrimPrefix(value, shadowIdentifierBase)
	if len(suffix) != 32 || suffix != strings.ToLower(suffix) {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

func expandIdentifier(template, root string) (string, error) {
	if !validIdentifierTemplate(template) || !validShadowIdentifier(root) {
		return "", errors.New("static Shadow identifier binding is invalid")
	}
	return strings.Replace(template, ShadowIdentifierToken, root, 1), nil
}

func (value Manifest) Validate() error {
	if value.Version != ManifestVersion || strings.TrimSpace(value.SourceVersion) == "" || strings.TrimSpace(value.SourceBuild) == "" ||
		len(value.SourceInventoryDigest) != 64 || len(value.SigningOrder) < 2 || len(value.SigningOrder) > maxSigningObjects {
		return errors.New("static Shadow transformation manifest header is invalid")
	}
	if _, err := hex.DecodeString(value.SourceInventoryDigest); err != nil || value.SourceInventoryDigest != strings.ToLower(value.SourceInventoryDigest) {
		return errors.New("static Shadow inventory digest is invalid")
	}
	seenTargets := map[string]bool{}
	for _, removal := range value.Removals {
		if !safeRelative(removal.Path, false) || (removal.Type != "file" && removal.Type != "directory" && removal.Type != "symlink") || seenTargets[removal.Path] {
			return errors.New("static Shadow removal is invalid or duplicated")
		}
		seenTargets[removal.Path] = true
	}
	seenRewrites := map[string]bool{}
	for _, rewrite := range value.Rewrites {
		rewriteKey := rewrite.Path + "\x00" + rewrite.Key
		if !safeRelative(rewrite.Path, false) || rewrite.Key == "" || rewrite.Expected == "" ||
			!validIdentifierTemplate(rewrite.Value) || seenRewrites[rewriteKey] || seenTargets[rewrite.Path] {
			return errors.New("static Shadow plist rewrite is invalid")
		}
		seenRewrites[rewriteKey] = true
	}
	seenCode := map[string]bool{}
	lastDepth := int(^uint(0) >> 1)
	for index, object := range value.SigningOrder {
		if !safeRelative(object.Path, true) || object.Role == "" || !validIdentifierTemplate(object.Identifier) ||
			!safeRelative(object.EntitlementsLeaf, false) || seenCode[object.Path] || pathDepth(object.Path) > lastDepth {
			return errors.New("static Shadow signing order is not unique deepest-first")
		}
		if index < len(value.SigningOrder)-1 && object.Path == "." || index == len(value.SigningOrder)-1 && object.Path != "." {
			return errors.New("static Shadow root code object must be signed last")
		}
		seenCode[object.Path] = true
		lastDepth = pathDepth(object.Path)
	}
	return nil
}

type InventoryEntry = shadowinventory.Entry

func Inventory(root string) ([]InventoryEntry, string, error) {
	return shadowinventory.Scan(root)
}

func trustedRoot(root string) (string, error) {
	return shadowinventory.TrustedRoot(root)
}

type Runner interface {
	Run(context.Context, string, ...string) error
	Output(context.Context, string, ...string) (string, error)
}

type ExecRunner struct{}

type cappedOutput struct {
	value    []byte
	overflow bool
}

func (value *cappedOutput) Write(payload []byte) (int, error) {
	remaining := 32*1024 - len(value.value)
	if remaining > 0 {
		if remaining > len(payload) {
			remaining = len(payload)
		}
		value.value = append(value.value, payload[:remaining]...)
	}
	if remaining < len(payload) {
		value.overflow = true
	}
	return len(payload), nil
}

func (ExecRunner) Run(ctx context.Context, name string, arguments ...string) error {
	if ctx == nil || !filepath.IsAbs(name) {
		return errors.New("bounded Shadow platform command input is invalid")
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	output := &cappedOutput{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || output.overflow {
		return errors.New("bounded Shadow platform command failed")
	}
	return nil
}

func (ExecRunner) Output(ctx context.Context, name string, arguments ...string) (string, error) {
	if ctx == nil || !filepath.IsAbs(name) {
		return "", errors.New("bounded Shadow platform query input is invalid")
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	output := &cappedOutput{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || output.overflow {
		return "", errors.New("bounded Shadow platform query failed")
	}
	return strings.TrimSpace(string(output.value)), nil
}

type StaticTransformer struct {
	BuildRoot string
	Runner    Runner
}

type Timings struct {
	Inventory time.Duration
	Rewrite   time.Duration
	Sign      time.Duration
	Verify    time.Duration
	Total     time.Duration
}

func exactTarget(root, relative string, allowRoot bool) (string, error) {
	if !safeRelative(relative, allowRoot) {
		return "", errors.New("static Shadow target is unsafe")
	}
	target := root
	if relative != "." {
		target = filepath.Join(root, relative)
	}
	clean := filepath.Clean(target)
	if clean != root && !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return "", errors.New("static Shadow target escaped its root")
	}
	if relative != "." {
		parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
		current := root
		for index := 0; index < len(parts)-1; index++ {
			current = filepath.Join(current, parts[index])
			info, err := os.Lstat(current)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("static Shadow target has a linked or invalid parent")
			}
		}
	}
	return clean, nil
}

func withinRoot(root, target string) bool {
	return shadowinventory.WithinRoot(root, target)
}

func targetType(info os.FileInfo) string {
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return "symlink"
	case info.IsDir():
		return "directory"
	case info.Mode().IsRegular():
		return "file"
	default:
		return "special"
	}
}

func (value StaticTransformer) Transform(ctx context.Context, root string, manifest Manifest, shadowIdentifier string) (Timings, error) {
	totalStart := time.Now()
	root, err := trustedRoot(root)
	buildRoot, buildRootErr := trustedRoot(value.BuildRoot)
	if ctx == nil || err != nil || buildRootErr != nil || manifest.Validate() != nil || !validShadowIdentifier(shadowIdentifier) {
		return Timings{}, errors.New("static Shadow transformation input is invalid")
	}
	if value.Runner == nil {
		value.Runner = ExecRunner{}
	}
	inventoryStart := time.Now()
	_, digest, err := Inventory(root)
	timings := Timings{Inventory: time.Since(inventoryStart)}
	if err != nil || digest != manifest.SourceInventoryDigest {
		return timings, errors.New("static Shadow source inventory drifted")
	}
	rewriteStart := time.Now()
	for _, removal := range manifest.Removals {
		target, err := exactTarget(root, removal.Path, false)
		if err != nil {
			return timings, err
		}
		info, err := os.Lstat(target)
		if err != nil || targetType(info) != removal.Type {
			return timings, errors.New("static Shadow removal target drifted")
		}
		if removal.Type == "directory" {
			err = os.RemoveAll(target)
		} else {
			err = os.Remove(target)
		}
		if err != nil {
			return timings, errors.New("static Shadow removal failed")
		}
	}
	for _, rewrite := range manifest.Rewrites {
		target, err := exactTarget(root, rewrite.Path, false)
		if err != nil {
			return timings, err
		}
		if info, err := os.Lstat(target); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return timings, errors.New("static Shadow plist target is invalid")
		}
		current, err := value.Runner.Output(ctx, "/usr/bin/plutil", "-extract", rewrite.Key, "raw", "-o", "-", target)
		if err != nil || current != rewrite.Expected {
			return timings, errors.New("static Shadow plist input drifted")
		}
		expanded, err := expandIdentifier(rewrite.Value, shadowIdentifier)
		if err != nil {
			return timings, err
		}
		if err := value.Runner.Run(ctx, "/usr/bin/plutil", "-replace", rewrite.Key, "-string", expanded, target); err != nil {
			return timings, err
		}
	}
	timings.Rewrite = time.Since(rewriteStart)
	signStart := time.Now()
	for _, object := range manifest.SigningOrder {
		target, err := exactTarget(root, object.Path, true)
		if err != nil {
			return timings, err
		}
		if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeSymlink != 0 ||
			(!info.IsDir() && !info.Mode().IsRegular()) {
			return timings, errors.New("static Shadow code object target is invalid")
		}
		entitlements, err := exactTarget(buildRoot, object.EntitlementsLeaf, false)
		if err != nil {
			return timings, err
		}
		info, err := os.Lstat(entitlements)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return timings, errors.New("static Shadow entitlement profile is invalid")
		}
		identifier, err := expandIdentifier(object.Identifier, shadowIdentifier)
		if err != nil {
			return timings, err
		}
		if err := value.Runner.Run(ctx, "/usr/bin/codesign", "--force", "--sign", "-", "--identifier", identifier,
			"--entitlements", entitlements, target); err != nil {
			return timings, err
		}
	}
	timings.Sign = time.Since(signStart)
	verifyStart := time.Now()
	if err := value.Runner.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", root); err != nil {
		return timings, errors.New("strict Shadow verification failed")
	}
	timings.Verify = time.Since(verifyStart)
	timings.Total = time.Since(totalStart)
	return timings, nil
}

func CanonicalManifest(value Manifest) ([]byte, string, error) {
	if err := value.Validate(); err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	payload = append(bytes.TrimSpace(payload), '\n')
	digest := sha256.Sum256(payload)
	return payload, hex.EncodeToString(digest[:]), nil
}
