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

// considerCapturedDatabaseKey 处理在 CommonCrypto 边界直接观察到的 key 参数。与宽泛的
// 内存候选不同，在执行目标数据库 HMAC 验证前，不得因 passphrase 形态启发式规则将其
// 丢弃。返回值表示是否获得绑定 target 的密码学接受结果，也包括重复观察到已接受密钥。
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
	// 保留高熵值供现有的有界替代解释使用，但不把该启发式规则作为接受原始密钥的前置条件。
	if isPotentialPassphrase(key) {
		collector.considerBinaryDatabaseKeyFrom(key, true, origin)
	}
	return accepted
}

func (collector *Collector) considerCapturedDatabaseKey(key []byte) bool {
	return collector.considerCapturedDatabaseKeyFrom(key, "commoncrypto_cccrypt")
}
