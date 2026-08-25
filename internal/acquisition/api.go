package acquisition

import (
	"bytes"
	"encoding/hex"

	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

func (collector *Collector) Scan(data []byte) { collector.scan(data) }

func (collector *Collector) ScanInternalXORKeys(data []byte) {
	collector.scanInternalXORKeys(data)
}

func (collector *Collector) CollectKeyObjects(data []byte, seen map[uint64]bool, readAt func(uint64, []byte) int) {
	collector.collectKeyObjects(data, seen, readAt)
}

func (collector *Collector) ScanSaltNeighborhood(data []byte) {
	collector.scanSaltNeighborhood(data)
}

func (collector *Collector) ScanDatabasePatternsFrom(data []byte, origin string) {
	collector.scanDatabasePatternsFrom(data, origin)
}

func (collector *Collector) ScanMediaPatterns(data []byte) {
	collector.scanMediaPatterns(data)
}

func (collector *Collector) ResolveDatabasePassphrase(remaining workbudget.Budget) {
	collector.resolveDatabasePassphrase(remaining)
}

func (collector *Collector) RecordGlobalPassphrase(candidate []byte, source string, completeCallEvidence bool) bool {
	return collector.recordGlobalPassphrase(candidate, source, completeCallEvidence)
}

func (collector *Collector) ConsiderGlobalPassphrase(candidate []byte) bool {
	return collector.considerGlobalPassphrase(candidate)
}

func (collector *Collector) ConsiderCapturedDatabaseKey(key []byte) bool {
	return collector.considerCapturedDatabaseKey(key)
}

func (collector *Collector) ConsiderCapturedDatabaseKeyFrom(key []byte, origin string) bool {
	return collector.considerCapturedDatabaseKeyFrom(key, origin)
}

func (collector *Collector) DatabaseKeys(targets Targets) (map[string]string, int) {
	return collector.databaseKeys(targets)
}

func (collector *Collector) ProfilesForKeys(keys map[string]string) map[string]string {
	return collector.profilesForKeys(keys)
}

func (collector *Collector) HasAllDatabaseCandidates() bool {
	return collector.hasAllDatabaseCandidates()
}

func (collector *Collector) ResolvedMedia(evidence MediaEvidence) *protocolmodel.ImageKeys {
	return collector.resolvedMedia(evidence)
}

func (collector *Collector) ApplyScanDiagnostics(diag *diagnosticmodel.Diagnostics, keys map[string]string, ambiguous int, derivedMedia *protocolmodel.ImageKeys, media MediaEvidence) *protocolmodel.ImageKeys {
	return collector.applyScanDiagnostics(diag, keys, ambiguous, derivedMedia, media)
}

func (collector *Collector) MergeValidatedFrom(other *Collector) {
	collector.mergeValidatedFrom(other)
}

func (collector *Collector) ClearSensitiveBuffers() {
	collector.clearSensitiveBuffers()
}

func (collector *Collector) SetProcessInstanceID(id string) {
	collector.processInstanceID = id
}

func (collector *Collector) NewIsolated() *Collector {
	return NewCollector(
		collector.targets,
		MediaEvidence{V2Blocks: collector.mediaBlocks},
		collector.runtime,
		collector.validationBudget,
	)
}

func (collector *Collector) CandidateObservationCount() int {
	return len(collector.seenDatabase) + collector.candidateObservationCount
}

func (collector *Collector) TargetSaltMatches(salt []byte) bool {
	if len(salt) != 16 {
		return false
	}
	for _, target := range collector.targets.Pages {
		decoded, err := hex.DecodeString(target.Salt)
		if err == nil && bytes.Equal(decoded, salt) {
			return true
		}
	}
	return false
}

// ConsiderCapturedHMACKey handles the PBKDF rounds=2 CommonCrypto evidence,
// where the observed salt is the file salt XORed by the registered profile's
// HMAC mask and the observed password is the effective raw database key.
func (collector *Collector) ConsiderCapturedHMACKey(key, observedSalt []byte, origin string) bool {
	if len(key) != 32 {
		return false
	}
	accepted := false
	for _, target := range collector.targets.Pages {
		fileSalt, err := hex.DecodeString(target.Salt)
		if err != nil {
			continue
		}
		for _, profile := range collector.runtime.Profiles {
			if target.ProfileID != "" && target.ProfileID != profile.ID || len(fileSalt) != len(observedSalt) {
				continue
			}
			matches := true
			for index := range fileSalt {
				if fileSalt[index]^profile.HMACSaltXORMask != observedSalt[index] {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
			if providercrypto.VerifyRawKeyWithProfile(
				profile, key, target.Data, collector.runtime.cryptoRuntime(nil),
			) {
				accepted = true
				collector.addDatabaseCandidate(target.Path, hex.EncodeToString(key), profile.ID, origin)
			}
		}
	}
	return accepted
}
