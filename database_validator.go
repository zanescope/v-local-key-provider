package provider

import (
	"crypto/aes"
	"encoding/hex"
)

func xorBlock(block, previous []byte) []byte {
	plain := make([]byte, aes.BlockSize)
	for index := range plain {
		plain[index] = block[index] ^ previous[index]
	}
	return plain
}

func validSQLitePageHeader(plain []byte, reserve int, offset int) bool {
	return validSQLitePageHeaderForPageSize(plain, 0, reserve, offset)
}

func validSQLitePageHeaderForPageSize(plain []byte, expectedPageSize, reserve int, offset int) bool {
	if offset == 0 {
		if len(plain) < 24 || string(plain[:16]) != "SQLite format 3\x00" {
			return false
		}
		plain = plain[16:]
	}
	if len(plain) < 8 {
		return false
	}
	// SQLite 头部把 64 KiB 页编码为字段值 1（两字节无法直接表示 65536）。
	// 先翻译这个约定，否则 pageSize == 65536 的判断永远取不到。
	pageSize := int(plain[0])<<8 | int(plain[1])
	if pageSize == 1 {
		pageSize = 65536
	}
	validPageSize := pageSize >= 512 && pageSize <= 65536 && pageSize&(pageSize-1) == 0
	if expectedPageSize > 0 && pageSize != expectedPageSize {
		return false
	}
	return validPageSize && int(plain[4]) == reserve && plain[5] == 64 && plain[6] == 32 && plain[7] == 32
}

func validateRawDatabaseKey(key, page []byte) bool {
	_, valid := verifyRawDatabaseKey(key, page, nil)
	return valid
}

func (collector *candidateCollector) ensureDatabaseCandidate(databasePath, effectiveKey, profileID string) (*databaseCandidateInfo, bool) {
	if collector.databaseCandidates[databasePath] == nil {
		collector.databaseCandidates[databasePath] = map[string]*databaseCandidateInfo{}
	}
	information := collector.databaseCandidates[databasePath][effectiveKey]
	if information != nil {
		return information, false
	}
	information = &databaseCandidateInfo{profileID: profileID, origins: map[string]bool{}}
	collector.databaseCandidates[databasePath][effectiveKey] = information
	return information, true
}

func (collector *candidateCollector) addDatabaseCandidate(databasePath, effectiveKey, profileID, origin string) {
	information, added := collector.ensureDatabaseCandidate(databasePath, effectiveKey, profileID)
	information.origins[origin] = true
	if collector.processInstanceID != "" {
		information.origins[candidateProcessInstanceSourcePrefix+collector.processInstanceID] = true
	}
	if added {
		collector.validatedDatabaseCandidateCount++
	}
}

func (collector *candidateCollector) validateDatabaseCandidateFrom(candidate, saltHint string, targets databaseTargets, origin string) {
	key, err := hex.DecodeString(candidate)
	if err != nil || len(key) != 32 {
		return
	}
	for _, target := range targets.pages {
		if saltHint != "" && target.salt != saltHint {
			continue
		}
		verification, valid := verifyRawDatabaseKey(key, target.data, nil)
		if valid && (target.profileID == "" || verification.ProfileID == target.profileID) {
			collector.addDatabaseCandidate(target.path, verification.KeyHex, verification.ProfileID, "raw_enc_key")
			if origin != "" && origin != "raw_enc_key" {
				collector.addDatabaseCandidate(target.path, verification.KeyHex, verification.ProfileID, origin)
			}
		}
	}
}

func (collector *candidateCollector) validateDatabaseCandidate(candidate, saltHint string, targets databaseTargets) {
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

func (collector *candidateCollector) considerBinaryDatabaseKeyFrom(key []byte, preferred bool, origin string) {
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
	for _, target := range collector.targets.pages {
		verification, valid := verifyRawDatabaseKey(key, target.data, nil)
		if valid {
			collector.addDatabaseCandidate(target.path, verification.KeyHex, verification.ProfileID, "raw_enc_key")
			if origin != "" && origin != "raw_enc_key" {
				collector.addDatabaseCandidate(target.path, verification.KeyHex, verification.ProfileID, origin)
			}
		}
	}
	if len(collector.binaryCandidates)+len(collector.binaryFallbackCandidates) >= maxBinaryCandidateCount {
		collector.databaseScanLimited = true
		return
	}
	copyOfKey := append([]byte(nil), key...)
	if preferred {
		collector.binaryCandidates = append(collector.binaryCandidates, copyOfKey)
	} else {
		collector.binaryFallbackCandidates = append(collector.binaryFallbackCandidates, copyOfKey)
	}
}

func (collector *candidateCollector) considerBinaryDatabaseKey(key []byte, preferred bool) {
	collector.considerBinaryDatabaseKeyFrom(key, preferred, "structured_memory")
}

// considerCapturedDatabaseKey handles a key argument observed directly at a
// CommonCrypto boundary. Unlike broad memory candidates, it must not be
// discarded by passphrase-shape heuristics before target database HMAC
// validation. The return value reports target-bound cryptographic acceptance,
// including duplicate observations of an already accepted key.
func (collector *candidateCollector) considerCapturedDatabaseKeyFrom(key []byte, origin string) bool {
	if len(key) != 32 {
		return false
	}
	accepted := false
	for _, target := range collector.targets.pages {
		verification, valid := verifyRawDatabaseKey(key, target.data, nil)
		if !valid || target.profileID != "" && verification.ProfileID != target.profileID {
			continue
		}
		accepted = true
		collector.addDatabaseCandidate(target.path, verification.KeyHex, verification.ProfileID, "raw_enc_key")
		if origin != "" && origin != "raw_enc_key" {
			collector.addDatabaseCandidate(target.path, verification.KeyHex, verification.ProfileID, origin)
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

func (collector *candidateCollector) considerCapturedDatabaseKey(key []byte) bool {
	return collector.considerCapturedDatabaseKeyFrom(key, "commoncrypto_cccrypt")
}
