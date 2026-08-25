package provider

import credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"

const candidateProcessInstanceSourcePrefix = credentialmodel.ProcessInstanceSourcePrefix

type databaseCredential = credentialmodel.DatabaseCredential
type credentialRoot = credentialmodel.Root
type credentialOverride = credentialmodel.Override

func credentialOverrideEvidence(origins map[string]bool) []string {
	return credentialmodel.OverrideEvidence(origins)
}

func credentialProcessInstanceEvidence(origins map[string]bool) []string {
	return credentialmodel.ProcessInstanceEvidence(origins)
}

func randomOpaqueID() (string, error) {
	return credentialmodel.RandomOpaqueID()
}

func (collector *candidateCollector) databaseCredential(keys map[string]string, targets databaseTargets) (*databaseCredential, error) {
	candidates := make(map[string]map[string]credentialmodel.CandidateEvidence, len(collector.databaseCandidates))
	for path, values := range collector.databaseCandidates {
		converted := make(map[string]credentialmodel.CandidateEvidence, len(values))
		for key, information := range values {
			if information == nil {
				continue
			}
			converted[key] = credentialmodel.CandidateEvidence{
				ProfileID: information.profileID,
				Origins:   information.origins,
			}
		}
		candidates[path] = converted
	}
	passphrases := make(map[string]credentialmodel.PassphraseEvidence, len(collector.globalPassphrases))
	for id, evidence := range collector.globalPassphrases {
		if evidence == nil {
			continue
		}
		passphrases[id] = credentialmodel.PassphraseEvidence{
			Secret: evidence.secret, Paths: evidence.paths, Sources: evidence.sources,
			CompleteCallEvidence: evidence.completeCallEvidence,
		}
	}
	return credentialmodel.Build(credentialmodel.BuildInput{
		Keys: keys, Catalog: targets.catalog, Candidates: candidates, GlobalPassphrases: passphrases,
	}, randomOpaqueID)
}
