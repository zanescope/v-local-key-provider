// Package credential owns the structured credential DTO and the policy that
// promotes verified candidate evidence into account roots or per-database
// overrides. It depends only on catalog evidence, never collector or platform
// implementation state.
package credential

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
)

const ProcessInstanceSourcePrefix = "process_instance:"

type DatabaseCredential struct {
	Mode             string              `json:"mode"`
	CredentialEpoch  string              `json:"credential_epoch"`
	AccountBindingID string              `json:"account_binding_id"`
	Roots            []Root              `json:"roots,omitempty"`
	Overrides        map[string]Override `json:"overrides,omitempty"`
}

type Root struct {
	CredentialID        string   `json:"credential_id"`
	Kind                string   `json:"kind"`
	ProfileID           string   `json:"profile_id"`
	Secret              string   `json:"secret"`
	Scope               string   `json:"scope"`
	VerifiedCatalogID   string   `json:"verified_catalog_id"`
	VerifiedDatabaseIDs []string `json:"verified_database_ids"`
	SourceEvidence      []string `json:"source_evidence"`
	ProcessInstanceIDs  []string `json:"process_instance_ids,omitempty"`
}

type Override struct {
	Kind               string   `json:"kind"`
	ProfileID          string   `json:"profile_id"`
	Secret             string   `json:"secret"`
	RelativePath       string   `json:"relative_path"`
	SourceEvidence     []string `json:"source_evidence"`
	ProcessInstanceIDs []string `json:"process_instance_ids,omitempty"`
}

type CandidateEvidence struct {
	ProfileID string
	Origins   map[string]bool
}

type PassphraseEvidence struct {
	Secret               []byte
	Paths                map[string]bool
	Sources              map[string]bool
	CompleteCallEvidence bool
}

type BuildInput struct {
	Keys              map[string]string
	Catalog           catalogmodel.Catalog
	Candidates        map[string]map[string]CandidateEvidence
	GlobalPassphrases map[string]PassphraseEvidence
}

func OverrideEvidence(origins map[string]bool) []string {
	values := make([]string, 0, len(origins)+1)
	if origins["global_passphrase"] {
		values = append(values, "passphrase_validation_unproven_global")
	}
	for origin := range origins {
		if strings.HasPrefix(origin, ProcessInstanceSourcePrefix) {
			continue
		}
		switch origin {
		case "", "raw_enc_key", "global_passphrase":
			continue
		default:
			values = append(values, origin)
		}
	}
	if len(values) == 0 {
		values = append(values, "process_memory")
	}
	sort.Strings(values)
	return values
}

func ProcessInstanceEvidence(origins map[string]bool) []string {
	values := []string{}
	for origin := range origins {
		if strings.HasPrefix(origin, ProcessInstanceSourcePrefix) {
			instanceID := strings.TrimPrefix(origin, ProcessInstanceSourcePrefix)
			if instanceID != "" {
				values = append(values, instanceID)
			}
		}
	}
	sort.Strings(values)
	return values
}

func RandomOpaqueID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("无法生成凭据标识")
	}
	return hex.EncodeToString(value), nil
}

func Build(input BuildInput, newOpaqueID func() (string, error)) (*DatabaseCredential, error) {
	if len(input.Keys) == 0 {
		return nil, nil
	}
	if newOpaqueID == nil {
		newOpaqueID = RandomOpaqueID
	}
	epoch, err := newOpaqueID()
	if err != nil {
		return nil, err
	}
	result := &DatabaseCredential{
		CredentialEpoch: epoch,
		Overrides:       map[string]Override{},
	}
	databaseByPath := map[string]catalogmodel.Database{}
	for _, database := range input.Catalog.Databases {
		databaseByPath[database.RelativePath] = database
	}
	type rootGroup struct {
		profileID   string
		databaseIDs []string
		paths       map[string]bool
		salts       map[string]bool
	}
	rootPaths := map[string]bool{}
	passphraseIDs := make([]string, 0, len(input.GlobalPassphrases))
	for id := range input.GlobalPassphrases {
		passphraseIDs = append(passphraseIDs, id)
	}
	sort.Strings(passphraseIDs)
	for _, passphraseID := range passphraseIDs {
		evidence := input.GlobalPassphrases[passphraseID]
		rootGroups := map[string]*rootGroup{}
		for path := range evidence.Paths {
			key, selected := input.Keys[path]
			database, found := databaseByPath[path]
			information := input.Candidates[path][key]
			if !selected || !found || !information.Origins["global_passphrase"] {
				continue
			}
			group := rootGroups[information.ProfileID]
			if group == nil {
				group = &rootGroup{profileID: information.ProfileID, paths: map[string]bool{}, salts: map[string]bool{}}
				rootGroups[information.ProfileID] = group
			}
			group.databaseIDs = append(group.databaseIDs, database.DatabaseID)
			group.paths[path] = true
			if database.Salt != "" {
				group.salts[database.Salt] = true
			}
		}
		if len(evidence.Secret) != 32 || !evidence.CompleteCallEvidence {
			continue
		}
		profiles := make([]string, 0, len(rootGroups))
		for profileID := range rootGroups {
			profiles = append(profiles, profileID)
		}
		sort.Strings(profiles)
		for _, profileID := range profiles {
			group := rootGroups[profileID]
			if len(group.salts) < 2 {
				continue
			}
			rootID, err := newOpaqueID()
			if err != nil {
				return nil, err
			}
			sort.Strings(group.databaseIDs)
			sourceEvidence := []string{"multiple_salt_hmac"}
			processInstanceIDs := []string{}
			for source := range evidence.Sources {
				if strings.HasPrefix(source, ProcessInstanceSourcePrefix) {
					processInstanceIDs = append(processInstanceIDs, strings.TrimPrefix(source, ProcessInstanceSourcePrefix))
				} else {
					sourceEvidence = append(sourceEvidence, source)
				}
			}
			sort.Strings(sourceEvidence)
			sort.Strings(processInstanceIDs)
			result.Roots = append(result.Roots, Root{
				CredentialID: rootID, Kind: "global_passphrase", ProfileID: group.profileID,
				Secret: hex.EncodeToString(evidence.Secret), Scope: "account",
				VerifiedCatalogID: input.Catalog.CatalogID, VerifiedDatabaseIDs: group.databaseIDs,
				SourceEvidence: sourceEvidence, ProcessInstanceIDs: processInstanceIDs,
			})
			for path := range group.paths {
				rootPaths[path] = true
			}
		}
	}
	for path, key := range input.Keys {
		if rootPaths[path] {
			continue
		}
		database, found := databaseByPath[path]
		if !found {
			continue
		}
		information, found := input.Candidates[path][key]
		if !found {
			continue
		}
		result.Overrides[database.DatabaseID] = Override{
			Kind: "raw_enc_key", ProfileID: information.ProfileID,
			Secret: key, RelativePath: path, SourceEvidence: OverrideEvidence(information.Origins),
			ProcessInstanceIDs: ProcessInstanceEvidence(information.Origins),
		}
	}
	switch {
	case len(result.Roots) > 0 && len(result.Overrides) > 0:
		result.Mode = "mixed"
	case len(result.Roots) > 0:
		result.Mode = "global_passphrase"
	default:
		result.Mode = "per_database"
	}
	return result, nil
}
