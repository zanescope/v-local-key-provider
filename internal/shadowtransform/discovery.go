package shadowtransform

import (
	"errors"
	"sort"
	"strings"
)

type DiscoveryInput struct {
	SourceVersion         string
	SourceBuild           string
	SourceInventoryDigest string
	RewriteInputs         []PlistRewrite
}

type EntitlementProfile struct {
	Leaf    string
	Payload []byte
}

type Discovery struct {
	Manifest Manifest
	Profiles []EntitlementProfile
}

func (value DiscoveryInput) validate() error {
	if strings.TrimSpace(value.SourceVersion) == "" || strings.TrimSpace(value.SourceBuild) == "" ||
		len(value.SourceInventoryDigest) != 64 || len(value.RewriteInputs) == 0 {
		return errors.New("Shadow discovery input is incomplete")
	}
	for index, rewrite := range value.RewriteInputs {
		if !safeRelative(rewrite.Path, false) || strings.TrimSpace(rewrite.Key) == "" ||
			strings.TrimSpace(rewrite.Expected) == "" || rewrite.Value != "" {
			return errors.New("Shadow discovery rewrite input is invalid")
		}
		if index > 0 {
			previous := value.RewriteInputs[index-1].Path + "\x00" + value.RewriteInputs[index-1].Key
			current := rewrite.Path + "\x00" + rewrite.Key
			if previous >= current {
				return errors.New("Shadow discovery rewrite input is not canonical")
			}
		}
	}
	return nil
}

func (value Discovery) Validate() error {
	if err := value.Manifest.Validate(); err != nil || len(value.Profiles) == 0 {
		return errors.New("Shadow discovery is invalid")
	}
	used := map[string]bool{}
	for _, object := range value.Manifest.SigningOrder {
		used[object.EntitlementsLeaf] = true
	}
	for index, profile := range value.Profiles {
		if !safeRelative(profile.Leaf, false) || len(profile.Payload) == 0 || !used[profile.Leaf] {
			return errors.New("Shadow discovery entitlement profile is invalid or unused")
		}
		if index > 0 && value.Profiles[index-1].Leaf >= profile.Leaf {
			return errors.New("Shadow discovery entitlement profiles are not canonical")
		}
		delete(used, profile.Leaf)
	}
	if len(used) != 0 {
		return errors.New("Shadow discovery lacks a referenced entitlement profile")
	}
	return nil
}

func sortProfiles(values []EntitlementProfile) {
	sort.Slice(values, func(left, right int) bool { return values[left].Leaf < values[right].Leaf })
}
