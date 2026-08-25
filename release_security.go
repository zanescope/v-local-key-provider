package provider

import (
	"errors"
	"path/filepath"
	"strings"
)

// buildMode is stamped to "release" by every signed release build. Keeping the
// default development value lets source builds and protocol fixtures remain
// usable without weakening the signed distribution.
var buildMode = "development"

// releaseSignerSHA256 is injected into Windows release binaries before signing.
// Runtime Authenticode validation must match this exact leaf certificate, not
// merely any certificate trusted by the current machine.
var releaseSignerSHA256 string

// releasePromotionSHA256 is the content digest of the external promotion
// manifest validated by the signed release builder. The manifest is deliberately
// not compiled into the live-tested candidate: it binds that candidate to its
// content-addressed real-device evidence without creating a binary/evidence hash
// cycle.
var releasePromotionSHA256 string

func releaseBuild() bool {
	return strings.EqualFold(strings.TrimSpace(buildMode), "release")
}

func releasePromotionReady() bool {
	return validWindowsSHA256(strings.ToLower(strings.TrimSpace(releasePromotionSHA256)))
}

func validateReleaseCompatibilityRegistry(platform, architecture string, windowsEntries []windowsCompatibilityEntry, darwinEntries []darwinCompatibilityEntry) error {
	switch platform {
	case "windows":
		for _, entry := range windowsEntries {
			if entry.ProcessArchitecture == architecture && windowsRegistryEntryEligible(entry) {
				return nil
			}
		}
	case "darwin":
		for _, entry := range darwinEntries {
			if entry.ProcessArchitecture == architecture && darwinRegistryEntryEligible(entry) {
				return nil
			}
		}
	default:
		return errors.New("release compatibility target is unsupported")
	}
	return errors.New("release compatibility registry has no complete candidate entry for target")
}

func releaseCompatibilityReadiness(platform, architecture string) error {
	return validateReleaseCompatibilityRegistry(
		strings.ToLower(strings.TrimSpace(platform)), strings.ToLower(strings.TrimSpace(architecture)),
		windowsCompatibilityRegistry, darwinCompatibilityRegistry,
	)
}

func runtimeRole() string {
	arguments := processArguments()
	if len(arguments) < 2 {
		return "provider"
	}
	switch arguments[1] {
	case "helper-acquire", "helper-acquire-loopback":
		return "helper"
	case "internal-hook-watchdog":
		name := strings.TrimSuffix(strings.ToLower(filepath.Base(arguments[0])), ".exe")
		if name == "v-local-key-provider-helper" {
			return "helper"
		}
	case "daemon":
		if len(arguments) >= 3 && arguments[2] == "serve-helper" {
			return "helper"
		}
	}
	return "provider"
}

var processArguments = func() []string { return processArgs() }
