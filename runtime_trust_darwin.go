//go:build darwin

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	darwinProviderCodeIdentifier = "com.zanescope.v-local-key-provider"
	darwinHelperCodeIdentifier   = "com.zanescope.v-local-key-provider.helper"
)

type darwinCodeIdentity struct {
	identifier                string
	teamID                    string
	designatedRequirementHash string
	developerID               bool
}

func trustedDarwinDirectoryTree(directory string) error {
	uid := uint32(os.Geteuid())
	for current := filepath.Clean(directory); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("component directory tree is not direct")
		}
		resolved, err := filepath.EvalSymlinks(current)
		if err != nil || !sameCanonicalPath(current, resolved) {
			return errors.New("component directory tree is not canonical")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != uid && stat.Uid != 0) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("component directory tree owner or write permissions are not trusted")
		}
		if parent := filepath.Dir(current); parent == current {
			return nil
		}
	}
}

func trustedDarwinExecutable(path, expectedName string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Base(absolute) != expectedName {
		return "", errors.New("component path or name is not fixed")
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0o111 == 0 {
		return "", errors.New("component is not a directly installed executable")
	}
	parent := filepath.Dir(absolute)
	if err := trustedDarwinDirectoryTree(parent); err != nil {
		return "", err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("component parent is not a direct directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || !sameCanonicalPath(parent, resolvedParent) {
		return "", errors.New("component parent contains a symbolic link")
	}
	fileStat, fileOK := info.Sys().(*syscall.Stat_t)
	uid := uint32(os.Geteuid())
	if !fileOK || (fileStat.Uid != uid && fileStat.Uid != 0) || info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("component owner or write permissions are not trusted")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || !sameCanonicalPath(absolute, resolved) {
		return "", errors.New("component path is not canonical")
	}
	return absolute, nil
}

func runCodesign(arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	output, err := runBoundedDarwinCombinedOutput(ctx, "/usr/bin/codesign", arguments, 256*1024)
	if ctx.Err() != nil {
		zeroBytes(output)
		return nil, errors.New("codesign verification timed out")
	}
	return output, err
}

func darwinCodeIdentityFor(path, expectedIdentifier string, requireDeveloperID bool) (darwinCodeIdentity, error) {
	verified, err := runCodesign("--verify", "--strict", "--verbose=2", path)
	zeroBytes(verified)
	if err != nil {
		return darwinCodeIdentity{}, errors.New("component code signature is invalid")
	}
	details, err := runCodesign("--display", "--verbose=4", path)
	defer zeroBytes(details)
	if err != nil {
		return darwinCodeIdentity{}, errors.New("component code identity is unavailable")
	}
	requirement, err := runCodesign("--display", "--requirements", "-", path)
	defer zeroBytes(requirement)
	if err != nil {
		return darwinCodeIdentity{}, errors.New("component designated requirement is unavailable")
	}
	identity := darwinCodeIdentity{}
	for _, line := range strings.Split(string(details), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Identifier="):
			identity.identifier = strings.TrimSpace(strings.TrimPrefix(line, "Identifier="))
		case strings.HasPrefix(line, "TeamIdentifier="):
			identity.teamID = strings.TrimSpace(strings.TrimPrefix(line, "TeamIdentifier="))
		case strings.HasPrefix(line, "Authority=Developer ID Application:"):
			identity.developerID = true
		}
	}
	normalizedRequirement := strings.TrimSpace(string(requirement))
	digest := sha256.Sum256([]byte(normalizedRequirement))
	identity.designatedRequirementHash = hex.EncodeToString(digest[:])
	if identity.identifier != expectedIdentifier {
		return darwinCodeIdentity{}, errors.New("component code identifier is not the release identifier")
	}
	if requireDeveloperID && (identity.teamID == "" || !identity.developerID ||
		!strings.Contains(normalizedRequirement, "anchor apple generic")) {
		return darwinCodeIdentity{}, errors.New("component is not bound to a Developer ID designated requirement")
	}
	return identity, nil
}

func validateDarwinComponentPair(providerPath, helperPath string) error {
	provider, err := trustedDarwinExecutable(providerPath, "v-local-key-provider")
	if err != nil {
		return err
	}
	helper, err := trustedDarwinExecutable(helperPath, darwinHelperName)
	if err != nil || !sameCanonicalPath(filepath.Dir(provider), filepath.Dir(helper)) {
		return errors.New("helper is not a trusted fixed sibling of the Provider")
	}
	if !releaseBuild() {
		return nil
	}
	providerIdentity, err := darwinCodeIdentityFor(provider, darwinProviderCodeIdentifier, true)
	if err != nil {
		return err
	}
	helperIdentity, err := darwinCodeIdentityFor(helper, darwinHelperCodeIdentifier, true)
	if err != nil {
		return err
	}
	if providerIdentity.teamID == "" || providerIdentity.teamID != helperIdentity.teamID ||
		providerIdentity.designatedRequirementHash == "" || helperIdentity.designatedRequirementHash == "" {
		return errors.New("Provider and helper signing identities do not match")
	}
	return nil
}

func validateRuntimeComponent(role string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepathEvalCanonical(executable)
	if err != nil {
		return err
	}
	if role == "helper" {
		return validateDarwinComponentPair(filepath.Join(filepath.Dir(executable), "v-local-key-provider"), executable)
	}
	provider, err := trustedDarwinExecutable(executable, "v-local-key-provider")
	if err != nil {
		if releaseBuild() {
			return err
		}
		return nil
	}
	if releaseBuild() {
		_, err = darwinCodeIdentityFor(provider, darwinProviderCodeIdentifier, true)
	}
	return err
}

func validateAcquisitionClientPath(path string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || strings.TrimSpace(path) == "" {
		return "", errors.New("daemon client path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", errors.New("daemon client path is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return "", errors.New("daemon client is not an executable regular file")
	}
	if !releaseBuild() {
		return resolved, nil
	}
	client, err := trustedDarwinExecutable(resolved, "v-local-cli")
	if err != nil {
		return "", errors.New("release daemon client path is not trusted")
	}
	clientIdentity, err := darwinCodeIdentityFor(client, "com.zanescope.v-local-cli", true)
	if err != nil {
		return "", errors.New("release daemon client signature is invalid")
	}
	current, err := os.Executable()
	if err != nil {
		return "", err
	}
	current, err = filepathEvalCanonical(current)
	if err != nil {
		return "", err
	}
	identifier := darwinProviderCodeIdentifier
	if filepath.Base(current) == darwinHelperName {
		identifier = darwinHelperCodeIdentifier
	}
	currentIdentity, err := darwinCodeIdentityFor(current, identifier, true)
	if err != nil || currentIdentity.teamID == "" || currentIdentity.teamID != clientIdentity.teamID {
		return "", errors.New("daemon client and server signing teams do not match")
	}
	return client, nil
}

func acquisitionDaemonRuntimeContext(advertisedProviderPath string) (bool, string, error) {
	if advertisedProviderPath == "" {
		return false, "", validateRuntimeComponent("provider")
	}
	helper, err := os.Executable()
	if err != nil {
		return false, "", err
	}
	helper, err = filepathEvalCanonical(helper)
	if err != nil {
		return false, "", err
	}
	if err := validateDarwinComponentPair(advertisedProviderPath, helper); err != nil {
		return false, "untrusted", err
	}
	return true, "used", nil
}
