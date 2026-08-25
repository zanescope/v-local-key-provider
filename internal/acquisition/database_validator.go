package acquisition

import (
	"encoding/hex"
)

func (collector *Collector) ensureDatabaseCandidate(databasePath, effectiveKey, profileID string) (*databaseCandidateInfo, bool) {
	if collector.databaseCandidates[databasePath] == nil {
		collector.databaseCandidates[databasePath] = map[string]*databaseCandidateInfo{}
	}
	information := collector.databaseCandidates[databasePath][effectiveKey]
	if information != nil {
		return information, false
	}
	information = &databaseCandidateInfo{ProfileID: profileID, origins: map[string]bool{}}
	collector.databaseCandidates[databasePath][effectiveKey] = information
	return information, true
}

func (collector *Collector) addDatabaseCandidate(databasePath, effectiveKey, profileID, origin string) {
	information, added := collector.ensureDatabaseCandidate(databasePath, effectiveKey, profileID)
	information.origins[origin] = true
	if collector.processInstanceID != "" {
		information.origins[candidateProcessInstanceSourcePrefix+collector.processInstanceID] = true
	}
	if added {
		collector.validatedDatabaseCandidateCount++
	}
}

func (collector *Collector) validateDatabaseCandidateFrom(candidate, saltHint string, targets databaseTargets, origin string) {
	key, err := hex.DecodeString(candidate)
	if err != nil || len(key) != 32 {
		return
	}
	for _, target := range targets.Pages {
		if saltHint != "" && target.Salt != saltHint {
			continue
		}
		verification, valid := collector.verifyRawDatabaseKey(key, target.Data, nil)
		if valid && (target.ProfileID == "" || verification.ProfileID == target.ProfileID) {
			collector.addDatabaseCandidate(target.Path, verification.KeyHex, verification.ProfileID, "raw_enc_key")
			if origin != "" && origin != "raw_enc_key" {
				collector.addDatabaseCandidate(target.Path, verification.KeyHex, verification.ProfileID, origin)
			}
		}
	}
}

func (collector *Collector) validateDatabaseCandidate(candidate, saltHint string, targets databaseTargets) {
	collector.validateDatabaseCandidateFrom(candidate, saltHint, targets, "bounded_hex")
}

func isPotentialPassphrase(key []byte) bool {
	if len(key) != 32 {
		return false
	}
	unique := map[byte]bool{}
	printable := 0
	for _, value := range key {
		unique[value] = true
		if value >= 32 && value <= 126 {
			printable++
		}
	}
	return len(unique) >= 15 && printable <= 24
}

func (collector *Collector) considerBinaryDatabaseKeyFrom(key []byte, preferred bool, origin string) {
	if !isPotentialPassphrase(key) {
		return
	}
	candidate := hex.EncodeToString(key)
	category := ":binary:fallback"
	if preferred {
		category = ":binary:preferred"
	}
	seenKey := candidate + category
	if collector.seenDatabase[seenKey] {
		return
	}
	if len(collector.seenDatabase) >= maxCandidateCount {
		collector.databaseScanLimited = true
		return
	}
	collector.seenDatabase[seenKey] = true
	collector.dereferencedKeyCandidateCount++
	for _, target := range collector.targets.Pages {
		verification, valid := collector.verifyRawDatabaseKey(key, target.Data, nil)
		if valid {
			collector.addDatabaseCandidate(target.Path, verification.KeyHex, verification.ProfileID, "raw_enc_key")
			if origin != "" && origin != "raw_enc_key" {
				collector.addDatabaseCandidate(target.Path, verification.KeyHex, verification.ProfileID, origin)
			}
		}
	}
	if len(collector.binaryCandidates)+len(collector.binaryFallbackCandidates) >= maxBinaryCandidateCount {
		collector.databaseScanLimited = true
		return
	}
	copyOfKey := collector.runtime.CloneSensitive(key)
	if preferred {
		collector.binaryCandidates = append(collector.binaryCandidates, copyOfKey)
	} else {
		collector.binaryFallbackCandidates = append(collector.binaryFallbackCandidates, copyOfKey)
	}
}

func (collector *Collector) considerBinaryDatabaseKey(key []byte, preferred bool) {
	collector.considerBinaryDatabaseKeyFrom(key, preferred, "structured_memory")
}

// considerCapturedDatabaseKey handles a key argument observed directly at a
// CommonCrypto boundary. Unlike broad memory candidates, it must not be
// discarded by passphrase-shape heuristics before target database HMAC
// validation. The return value reports target-bound cryptographic acceptance,
// including duplicate observations of an already accepted key.
func (collector *Collector) considerCapturedDatabaseKeyFrom(key []byte, origin string) bool {
	if len(key) != 32 {
		return false
	}
	accepted := false
	for _, target := range collector.targets.Pages {
		verification, valid := collector.verifyRawDatabaseKey(key, target.Data, nil)
		if !valid || target.ProfileID != "" && verification.ProfileID != target.ProfileID {
			continue
		}
		accepted = true
		collector.addDatabaseCandidate(target.Path, verification.KeyHex, verification.ProfileID, "raw_enc_key")
		if origin != "" && origin != "raw_enc_key" {
			collector.addDatabaseCandidate(target.Path, verification.KeyHex, verification.ProfileID, origin)
		}
	}
	// Retain high-entropy values for the existing bounded alternative
	// interpretation without making that heuristic a prerequisite for raw-key
	// acceptance.
	if isPotentialPassphrase(key) {
		collector.considerBinaryDatabaseKeyFrom(key, true, origin)
	}
	return accepted
}

func (collector *Collector) considerCapturedDatabaseKey(key []byte) bool {
	return collector.considerCapturedDatabaseKeyFrom(key, "commoncrypto_cccrypt")
}
