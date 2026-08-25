package provider

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func nextInstruction(data []byte, cursor int, marker []byte) (int, bool) {
	for gap := 3; gap <= 8; gap++ {
		position := cursor + gap
		if position+len(marker) <= len(data) && bytes.Equal(data[position:position+len(marker)], marker) {
			return position, true
		}
	}
	return 0, false
}

func v4InternalXORKeys(data []byte) [][]byte {
	marker := []byte{0x48, 0xba}
	finalMarker := []byte{0x48, 0x85, 0xc0}
	var results [][]byte
	for start := 0; start < len(data); {
		relative := bytes.Index(data[start:], marker)
		if relative < 0 {
			break
		}
		position := start + relative
		start = position + 1
		if position+10 > len(data) {
			continue
		}
		key := append([]byte(nil), data[position+2:position+10]...)
		cursor := position + 10
		valid := true
		for part := 1; part < 4; part++ {
			position, valid = nextInstruction(data, cursor, marker)
			if !valid || position+10 > len(data) {
				valid = false
				break
			}
			key = append(key, data[position+2:position+10]...)
			cursor = position + 10
		}
		if !valid {
			continue
		}
		if _, valid = nextInstruction(data, cursor, finalMarker); valid {
			results = append(results, key)
		}
	}
	return results
}

func (collector *candidateCollector) scanInternalXORKeys(data []byte) {
	for _, key := range v4InternalXORKeys(data) {
		fingerprint := string(key)
		if collector.seenInternalXORKeys[fingerprint] {
			continue
		}
		if len(collector.internalXORKeys) >= maxInternalXORKeyCount {
			collector.databaseScanLimited = true
			return
		}
		collector.seenInternalXORKeys[fingerprint] = true
		collector.internalXORKeys = append(collector.internalXORKeys, append([]byte(nil), key...))
		collector.internalXORKeyCandidateCount++
	}
}

func validateV4DatabasePassphrase(passphrase, page []byte, cancelled *atomic.Bool, remaining ...budget) bool {
	_, valid := verifyDatabasePassphrase(passphrase, page, cancelled, remaining...)
	return valid
}

func preferredDatabasePage(pages []databasePage) (databasePage, bool) {
	if len(pages) == 0 {
		return databasePage{}, false
	}
	for _, page := range pages {
		if strings.EqualFold(filepathBase(page.path), "message_0.db") {
			return page, true
		}
	}
	return pages[0], true
}

func filepathBase(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if index := strings.LastIndexByte(path, '/'); index >= 0 {
		return path[index+1:]
	}
	return path
}

// findV4DatabasePassphrase 在每个候选之前检查时限。单次验证实测约 164 毫秒，
// 因此超出时限的幅度被限制在一次验证以内；不在 KDF 中途中断，保持逻辑简单。
func findV4DatabasePassphrase(candidates [][]byte, page databasePage, remaining budget) ([]byte, int) {
	if len(candidates) == 0 {
		return nil, 0
	}
	workerCount := runtime.NumCPU()
	if workerCount > 2 {
		workerCount = 2
	}
	if workerCount > len(candidates) {
		workerCount = len(candidates)
	}
	jobs := make(chan []byte, len(candidates))
	for _, candidate := range candidates {
		jobs <- candidate
	}
	close(jobs)
	result := make(chan []byte, 1)
	var found atomic.Bool
	var tested atomic.Int64
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer workers.Done()
			for candidate := range jobs {
				if found.Load() || remaining.expired() {
					return
				}
				tested.Add(1)
				if validateV4DatabasePassphrase(candidate, page.data, &found, remaining) &&
					found.CompareAndSwap(false, true) {
					result <- append([]byte(nil), candidate...)
					return
				}
			}
		}()
	}
	workers.Wait()
	select {
	case candidate := <-result:
		return candidate, int(tested.Load())
	default:
		return nil, int(tested.Load())
	}
}

func (collector *candidateCollector) xorPassphraseCandidates(candidates [][]byte) [][]byte {
	seen := map[string]bool{}
	var transformed [][]byte
	for _, candidate := range candidates {
		for _, xorKey := range collector.internalXORKeys {
			if len(candidate) != 32 || len(xorKey) != 32 {
				continue
			}
			passphrase := make([]byte, 32)
			for index := range passphrase {
				passphrase[index] = candidate[index] ^ xorKey[index]
			}
			fingerprint := string(passphrase)
			if seen[fingerprint] {
				continue
			}
			if len(transformed) >= maxBinaryCandidateCount {
				collector.databaseScanLimited = true
				return transformed
			}
			seen[fingerprint] = true
			transformed = append(transformed, passphrase)
		}
	}
	return transformed
}

func (collector *candidateCollector) resolveDatabasePassphrase(remaining budget) {
	// 高成本 KDF 有独立于静态扫描和 hook 等待的阶段预算。整体请求 deadline 更短时，
	// cappedFor 会自动沿用更早的整体截止时间。
	remaining = remaining.cappedFor(20 * time.Second)
	page, ok := preferredDatabasePage(collector.targets.pages)
	if !ok {
		return
	}
	groups := [][][]byte{
		collector.xorPassphraseCandidates(collector.binaryCandidates),
		collector.xorPassphraseCandidates(collector.binaryFallbackCandidates),
		collector.binaryCandidates,
		collector.binaryFallbackCandidates,
	}
	var candidate []byte
	tested := 0
	for _, group := range groups {
		if remaining.expired() {
			collector.databaseScanLimited = true
			collector.kdfBudgetExhausted = true
			break
		}
		var groupTested int
		candidate, groupTested = findV4DatabasePassphrase(group, page, remaining)
		tested += groupTested
		if len(candidate) == 32 {
			break
		}
	}
	collector.passphraseValidationCount = tested
	if len(candidate) != 32 {
		return
	}
	collector.recordGlobalPassphraseWithin(candidate, "bounded_memory_passphrase_probe", false, remaining)
}

func (collector *candidateCollector) recordGlobalPassphrase(candidate []byte, source string, completeCallEvidence bool) bool {
	return collector.recordGlobalPassphraseWithin(candidate, source, completeCallEvidence, collector.validationBudget)
}

func (collector *candidateCollector) recordGlobalPassphraseWithin(candidate []byte, source string, completeCallEvidence bool, remaining budget) bool {
	if len(candidate) != 32 {
		return false
	}
	id := hex.EncodeToString(candidate)
	evidence := collector.globalPassphrases[id]
	if evidence == nil {
		evidence = &globalPassphraseEvidence{
			secret: cloneSensitiveBytes(candidate), paths: map[string]bool{}, sources: map[string]bool{},
		}
		collector.globalPassphrases[id] = evidence
	}
	if source != "" {
		evidence.sources[source] = true
	}
	if collector.processInstanceID != "" {
		evidence.sources[candidateProcessInstanceSourcePrefix+collector.processInstanceID] = true
	}
	evidence.completeCallEvidence = evidence.completeCallEvidence || completeCallEvidence
	matched := false
	type derivedProfileSalt struct {
		key      []byte
		computed bool
	}
	derived := map[string]*derivedProfileSalt{}
	defer func() {
		for _, value := range derived {
			zeroBytes(value.key)
		}
	}()
	for _, target := range collector.targets.pages {
		if remaining.expired() {
			collector.databaseScanLimited = true
			collector.kdfBudgetExhausted = true
			break
		}
		for _, profile := range profileRegistry {
			if target.profileID != "" && target.profileID != profile.ID || len(target.data) < profile.PlaintextHeaderSize {
				continue
			}
			cacheID := profile.ID + "\x00" + hex.EncodeToString(target.data[:profile.PlaintextHeaderSize])
			cached := derived[cacheID]
			if cached == nil {
				cached = &derivedProfileSalt{}
				derived[cacheID] = cached
			}
			if !cached.computed {
				cached.computed = true
				cached.key = deriveProfileKey(profile, candidate, target.data[:profile.PlaintextHeaderSize], nil, remaining)
			}
			if len(cached.key) != profile.KeySize {
				if remaining.expired() {
					collector.databaseScanLimited = true
					collector.kdfBudgetExhausted = true
				}
				continue
			}
			if !verifyRawKeyWithProfile(profile, cached.key, target.data, nil, remaining) {
				continue
			}
			keyHex := hex.EncodeToString(cached.key)
			collector.addDatabaseCandidate(target.path, keyHex, profile.ID, "global_passphrase")
			if source != "" && source != "global_passphrase" {
				collector.addDatabaseCandidate(target.path, keyHex, profile.ID, source)
			}
			evidence.paths[target.path] = true
			matched = true
			break
		}
	}
	if !matched && len(evidence.paths) == 0 {
		zeroBytes(evidence.secret)
		delete(collector.globalPassphrases, id)
	}
	return matched
}

func (collector *candidateCollector) considerGlobalPassphrase(candidate []byte) bool {
	matched := collector.recordGlobalPassphrase(candidate, "macos_pbkdf_hook", true)
	if matched {
		collector.passphraseValidationCount++
	}
	return matched
}

func v4DatabaseKeyObjects(data []byte) []v4DatabaseKeyObject {
	var objects []v4DatabaseKeyObject
	for start := 0; start < len(data); {
		relative := bytes.Index(data[start:], v4DatabaseKeyObjectPrefix)
		if relative < 0 {
			break
		}
		index := start + relative
		if index >= 8 && index+24 <= len(data) {
			pointer := binary.LittleEndian.Uint64(data[index-8 : index])
			capacity := binary.LittleEndian.Uint64(data[index+16 : index+24])
			if pointer > 0x10000 && pointer < 0x7fffffffffff && capacity >= 32 && capacity <= 4096 {
				objects = append(objects, v4DatabaseKeyObject{pointer: pointer, capacity: capacity})
			}
		}
		start = index + 1
	}
	return objects
}

// collectKeyObjects 把内存块里的 v4 密钥对象统计并解引用。readAt 抽掉了平台差异
// （Windows 的 ReadProcessMemory 与 macOS 的 mach_vm_read），成功读满 32 字节返回长度。
// 统计计数在指针去重之前累加，与去重后的候选解引用保持各自的语义。
func (collector *candidateCollector) collectKeyObjects(data []byte, seen map[uint64]bool, readAt func(pointer uint64, buffer []byte) int) {
	for _, object := range v4DatabaseKeyObjects(data) {
		collector.keyObjectStructuralCount++
		switch object.capacity {
		case 32:
			collector.keyObjectCapacity32Count++
		case 47:
			collector.keyObjectCapacity47Count++
		case 63:
			collector.keyObjectCapacity63Count++
		default:
			collector.keyObjectOtherCapacityCount++
		}
		preferred := object.capacity == 47
		if preferred {
			collector.keyObjectPatternCount++
		}
		if seen[object.pointer] {
			continue
		}
		seen[object.pointer] = true
		candidate := make([]byte, 32)
		if readAt(object.pointer, candidate) == len(candidate) {
			collector.considerBinaryDatabaseKeyFrom(candidate, preferred, "structured_memory")
		}
	}
}

// looksLikeBinaryDatabaseKey 过滤盐值邻域里明显不可能是密钥的 32 字节序列：全零、
// 或含连续两个 0x00（堆布局的 null 填充哨兵会制造大量此类误报）。真实随机密钥极少
// 出现连续 NUL，借此把兜底验证的规模压下来。
func looksLikeBinaryDatabaseKey(candidate []byte) bool {
	return len(candidate) == 32 && !bytes.Equal(candidate, zeroKey32) &&
		!bytes.Contains(candidate, []byte{0x00, 0x00})
}

func (collector *candidateCollector) hasCandidatesForSalt(salt string) bool {
	found := false
	for _, target := range collector.targets.pages {
		if !strings.EqualFold(target.salt, salt) {
			continue
		}
		found = true
		if len(collector.databaseCandidates[target.path]) == 0 {
			return false
		}
	}
	return found
}

// scanSaltNeighborhood 借鉴活跃同类项目（r266-tech/wxkey，算法源自 Thearas）的兜底
// 策略：在内存块里定位已知数据库盐值的二进制形式，把其邻域窗口内的每个 32 字节序列
// 当作 raw enc_key 候选验证。这能命中不再以 x'<key><salt>' 字面量出现、只把盐与密钥
// 相邻存放的 codec_ctx。只做低成本的原始密钥页头验证（validateRawDatabaseKey），不触发
// 256000 轮口令派生，因此成本可控。
func (collector *candidateCollector) scanSaltNeighborhood(data []byte) {
	for saltHex := range collector.targets.bySalt {
		saltHint := strings.ToLower(saltHex)
		// 只处理尚无候选的盐值（对应 r266 的 remaining 集合）：主路径一旦命中即跳过，
		// 把邻域兜底的成本约束在真正缺密钥的盐值上，避免拖慢每个内存块的扫描。
		if collector.hasCandidatesForSalt(saltHint) {
			continue
		}
		salt, err := hex.DecodeString(saltHex)
		if err != nil || len(salt) != 16 {
			continue
		}
		for searchStart := 0; searchStart < len(data); {
			relative := bytes.Index(data[searchStart:], salt)
			if relative < 0 {
				break
			}
			index := searchStart + relative
			searchStart = index + 1
			start := index - saltNeighborhoodWindow
			if start < 0 {
				start = 0
			}
			end := index + len(salt) + saltNeighborhoodWindow
			if end > len(data) {
				end = len(data)
			}
			for offset := start; offset+32 <= end; offset++ {
				candidate := data[offset : offset+32]
				if !looksLikeBinaryDatabaseKey(candidate) {
					continue
				}
				candidateHex := hex.EncodeToString(candidate)
				seenKey := candidateHex + ":neighbor:" + saltHint
				if collector.seenDatabase[seenKey] {
					continue
				}
				if len(collector.seenDatabase) >= maxCandidateCount {
					collector.databaseScanLimited = true
					return
				}
				collector.seenDatabase[seenKey] = true
				collector.validateDatabaseCandidateFrom(candidateHex, saltHint, collector.targets, "salt_neighborhood")
			}
		}
	}
}

func (collector *candidateCollector) scanDatabasePatternsFrom(data []byte, origin string) {
	for index := 0; index+minDatabaseHexLength+3 <= len(data); index++ {
		if (data[index] != 'x' && data[index] != 'X') || data[index+1] != '\'' {
			continue
		}
		end := index + 2
		for end < len(data) && end-(index+2) <= maxDatabaseHexLength && isHex(data[end]) {
			end++
		}
		hexLength := end - (index + 2)
		if end >= len(data) || data[end] != '\'' || hexLength < minDatabaseHexLength ||
			hexLength > maxDatabaseHexLength || hexLength%2 != 0 {
			continue
		}
		collector.hexPatternCount++
		candidate := strings.ToLower(string(data[index+2 : index+66]))
		saltHint := ""
		if hexLength > 64 && hexLength < 96 {
			continue
		}
		if hexLength >= 96 {
			saltHint = strings.ToLower(string(data[end-32 : end]))
			if !collector.salts[saltHint] {
				continue
			}
		}
		seenKey := candidate + ":" + saltHint
		if collector.seenDatabase[seenKey] {
			continue
		}
		if len(collector.seenDatabase) >= maxCandidateCount {
			collector.databaseScanLimited = true
			return
		}
		collector.seenDatabase[seenKey] = true
		if hexLength == 64 {
			collector.rawKeyCandidateCount++
		}
		collector.validateDatabaseCandidateFrom(candidate, saltHint, collector.targets, origin)
	}
}

func (collector *candidateCollector) scanDatabasePatterns(data []byte) {
	collector.scanDatabasePatternsFrom(data, "bounded_hex")
}

func (collector *candidateCollector) scanMediaPatterns(data []byte) {
	if len(collector.mediaBlocks) == 0 {
		return
	}
	for index := 0; index < len(data); {
		if !isHex(data[index]) {
			index++
			continue
		}
		end := index + 1
		for end < len(data) && isHex(data[end]) {
			end++
		}
		if end-index >= 16 && end-index <= 256 {
			for start := index; start+16 <= end; start++ {
				candidate := string(data[start : start+16])
				if collector.seenMedia[candidate] {
					continue
				}
				if len(collector.seenMedia) >= maxMediaCandidateCount {
					collector.mediaScanLimited = true
					return
				}
				collector.seenMedia[candidate] = true
				if collector.validateMediaAES(candidate) {
					collector.mediaCandidates[candidate] = true
				}
			}
		}
		index = end
	}
}

func (collector *candidateCollector) scan(data []byte) {
	collector.scanDatabasePatterns(data)
	collector.scanMediaPatterns(data)
}
