package acquisition

import credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"

const candidateProcessInstanceSourcePrefix = credentialmodel.ProcessInstanceSourcePrefix

func (collector *Collector) databaseCredential(keys map[string]string, targets Targets) (*credentialmodel.DatabaseCredential, error) {
	candidates := make(map[string]map[string]credentialmodel.CandidateEvidence, len(collector.databaseCandidates))
	for path, values := range collector.databaseCandidates {
		converted := make(map[string]credentialmodel.CandidateEvidence, len(values))
		for key, information := range values {
			if information == nil {
				continue
			}
			converted[key] = credentialmodel.CandidateEvidence{
				ProfileID: information.ProfileID,
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
		Keys: keys, Catalog: targets.Catalog, Candidates: candidates, GlobalPassphrases: passphrases,
	}, collector.runtime.NewOpaqueID)
}

func (collector *Collector) DatabaseCredential(keys map[string]string, targets Targets) (*credentialmodel.DatabaseCredential, error) {
	return collector.databaseCredential(keys, targets)
}
