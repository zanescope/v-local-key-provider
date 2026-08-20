package main

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	minDatabaseHexLength    = 64
	maxDatabaseHexLength    = 192
	maxCandidateCount       = 250_000
	maxBinaryCandidateCount = 10_000
	maxInternalXORKeyCount  = 256
	scanTailLength          = 255
	v4KDFIterations         = 256_000
	// maxScanRegionBytes 跳过超过此大小的单个内存区域（如 dyld 共享缓存按完整虚拟
	// 尺寸映射的只读段），避免把扫描预算浪费在不可能承载 SQLCipher 结构的巨型映射上。
	maxScanRegionBytes = 512 * 1024 * 1024
	// saltNeighborhoodWindow 是盐值邻域兜底扫描在盐值前后各展开的字节数。
	saltNeighborhoodWindow = 4096
)

var zeroKey32 = make([]byte, 32)

var v4DatabaseKeyObjectPrefix = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

type v4DatabaseKeyObject struct {
	pointer  uint64
	capacity uint64
}

type candidateCollector struct {
	targets                         databaseTargets
	salts                           map[string]bool
	databaseCandidates              map[string]map[string]bool
	mediaBlocks                     [][16]byte
	seenMedia                       map[string]bool
	mediaCandidates                 map[string]bool
	mediaScanLimited                bool
	seenDatabase                    map[string]bool
	binaryCandidates                [][]byte
	binaryFallbackCandidates        [][]byte
	internalXORKeys                 [][]byte
	seenInternalXORKeys             map[string]bool
	databaseScanLimited             bool
	hexPatternCount                 int
	rawKeyCandidateCount            int
	validatedDatabaseCandidateCount int
	keyObjectPatternCount           int
	dereferencedKeyCandidateCount   int
	passphraseValidationCount       int
	keyObjectStructuralCount        int
	keyObjectCapacity32Count        int
	keyObjectCapacity47Count        int
	keyObjectCapacity63Count        int
	keyObjectOtherCapacityCount     int
	internalXORKeyCandidateCount    int
}

func newCandidateCollector(targets databaseTargets, media mediaEvidence) *candidateCollector {
	collector := &candidateCollector{
		targets:             targets,
		salts:               map[string]bool{},
		databaseCandidates:  map[string]map[string]bool{},
		mediaBlocks:         media.v2Blocks,
		seenMedia:           map[string]bool{},
		mediaCandidates:     map[string]bool{},
		seenDatabase:        map[string]bool{},
		seenInternalXORKeys: map[string]bool{},
	}
	for salt := range targets.bySalt {
		collector.salts[strings.ToLower(salt)] = true
	}
	return collector
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func validImageHeader(plain []byte) bool {
	return len(plain) >= 4 && (plain[0] == 0xff && plain[1] == 0xd8 && plain[2] == 0xff ||
		string(plain[:4]) == "\x89PNG" || string(plain[:4]) == "wxgf" ||
		string(plain[:3]) == "GIF" || string(plain[:4]) == "RIFF")
}

func validateMediaAESBlocks(blocks [][16]byte, candidate string) bool {
	if len(blocks) == 0 || len(candidate) != 16 {
		return false
	}
	cipher, err := aes.NewCipher([]byte(candidate))
	if err != nil {
		return false
	}
	plain := make([]byte, aes.BlockSize)
	for _, encrypted := range blocks {
		cipher.Decrypt(plain, encrypted[:])
		if !validImageHeader(plain) {
			return false
		}
	}
	return true
}

func (collector *candidateCollector) validateMediaAES(candidate string) bool {
	return validateMediaAESBlocks(collector.mediaBlocks, candidate)
}

func xorBlock(block, previous []byte) []byte {
	plain := make([]byte, aes.BlockSize)
	for index := range plain {
		plain[index] = block[index] ^ previous[index]
	}
	return plain
}

func validSQLitePageHeader(plain []byte, reserve int, offset int) bool {
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
	return validPageSize && int(plain[4]) == reserve && plain[5] == 64 && plain[6] == 32 && plain[7] == 32
}

func validateRawDatabaseKey(key, page []byte) bool {
	if len(key) != 32 || len(page) < 4096 {
		return false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	for _, reserve := range []int{80, 48, 64, 32} {
		ivStart := 4096 - reserve
		iv := page[ivStart : ivStart+aes.BlockSize]
		for _, offset := range []int{16, 0} {
			needed := aes.BlockSize
			if offset == 0 {
				needed = 2 * aes.BlockSize
			}
			if offset+needed > ivStart {
				continue
			}
			decrypted := make([]byte, 0, needed)
			previous := iv
			for start := offset; start < offset+needed; start += aes.BlockSize {
				raw := make([]byte, aes.BlockSize)
				block.Decrypt(raw, page[start:start+aes.BlockSize])
				decrypted = append(decrypted, xorBlock(raw, previous)...)
				previous = page[start : start+aes.BlockSize]
			}
			if validSQLitePageHeader(decrypted, reserve, offset) {
				return true
			}
		}
	}
	return false
}

func (collector *candidateCollector) addDatabaseCandidate(salt, candidate string) {
	if collector.databaseCandidates[salt] == nil {
		collector.databaseCandidates[salt] = map[string]bool{}
	}
	if !collector.databaseCandidates[salt][candidate] {
		collector.databaseCandidates[salt][candidate] = true
		collector.validatedDatabaseCandidateCount++
	}
}

func (collector *candidateCollector) validateDatabaseCandidate(candidate, saltHint string, targets databaseTargets) {
	key, err := hex.DecodeString(candidate)
	if err != nil || len(key) != 32 {
		return
	}
	for _, target := range targets.pages {
		if saltHint != "" && target.salt != saltHint {
			continue
		}
		if validateRawDatabaseKey(key, target.data) {
			collector.addDatabaseCandidate(target.salt, candidate)
		}
	}
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

func (collector *candidateCollector) considerBinaryDatabaseKey(key []byte, preferred bool) {
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
		if validateRawDatabaseKey(key, target.data) {
			collector.addDatabaseCandidate(target.salt, candidate)
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

// pbkdf2SHA512 刻意不使用标准库的 crypto/pbkdf2.Key，因为后者不支持中途取消。
// 这里的 cancelled 钩子每 4096 轮检查一次：当某个 worker 已经命中口令时，其余
// worker 正在进行的这次 25.6 万轮派生可以立即放弃（实测省约 98%，约 155ms → 3ms），
// 这是并发暴力验证的关键优化，标准库替换不了。单密钥结果与标准库逐字节一致。
//
// 对比：对单个已知密钥只派生一次、串行验证的场景没有取消的用武之地，用标准库
// crypto/pbkdf2 即可。取舍依据始终是调用场景需不需要中途取消，而非是否手写——
// 不要因为别处换了实现就把这里也换掉。
func pbkdf2SHA512(password, salt []byte, iterations int, cancelled *atomic.Bool) []byte {
	if iterations <= 0 {
		return nil
	}
	blockInput := make([]byte, len(salt)+4)
	copy(blockInput, salt)
	binary.BigEndian.PutUint32(blockInput[len(salt):], 1)
	mac := hmac.New(sha512.New, password)
	_, _ = mac.Write(blockInput)
	u := mac.Sum(nil)
	result := append([]byte(nil), u...)
	for iteration := 1; iteration < iterations; iteration++ {
		if cancelled != nil && iteration%4096 == 0 && cancelled.Load() {
			return nil
		}
		mac.Reset()
		_, _ = mac.Write(u)
		u = mac.Sum(u[:0])
		for index := range result {
			result[index] ^= u[index]
		}
	}
	return append([]byte(nil), result[:32]...)
}

func validateV4DatabasePassphrase(passphrase, page []byte, cancelled *atomic.Bool) bool {
	if len(passphrase) != 32 || len(page) < 4096 {
		return false
	}
	salt := page[:16]
	encKey := pbkdf2SHA512(passphrase, salt, v4KDFIterations, cancelled)
	if len(encKey) != 32 {
		return false
	}
	macSalt := make([]byte, len(salt))
	for index := range salt {
		macSalt[index] = salt[index] ^ 0x3a
	}
	macKey := pbkdf2SHA512(encKey, macSalt, 2, cancelled)
	if len(macKey) != 32 {
		return false
	}
	mac := hmac.New(sha512.New, macKey)
	_, _ = mac.Write(page[16:4032])
	pageNumber := []byte{1, 0, 0, 0}
	_, _ = mac.Write(pageNumber)
	return hmac.Equal(mac.Sum(nil), page[4032:4096])
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
	if workerCount > 8 {
		workerCount = 8
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
				if validateV4DatabasePassphrase(candidate, page.data, &found) &&
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
	hexCandidate := hex.EncodeToString(candidate)
	for salt := range collector.targets.bySalt {
		collector.addDatabaseCandidate(strings.ToLower(salt), hexCandidate)
	}
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
			collector.considerBinaryDatabaseKey(candidate, preferred)
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

// scanSaltNeighborhood 借鉴活跃同类项目（r266-tech/wxkey，算法源自 Thearas）的兜底
// 策略：在内存块里定位已知数据库盐值的二进制形式，把其邻域窗口内的每个 32 字节序列
// 当作 raw enc_key 候选验证。这能命中不再以 x'<key><salt>' 字面量出现、只把盐与密钥
// 相邻存放的 codec_ctx。只做便宜的 raw key 页头验证（validateRawDatabaseKey），不触发
// 256000 轮口令派生，因此成本可控。
func (collector *candidateCollector) scanSaltNeighborhood(data []byte) {
	for saltHex := range collector.targets.bySalt {
		saltHint := strings.ToLower(saltHex)
		// 只处理尚无候选的盐值（对应 r266 的 remaining 集合）：主路径一旦命中即跳过，
		// 把邻域兜底的成本约束在真正缺密钥的盐值上，避免拖慢每个内存块的扫描。
		if len(collector.databaseCandidates[saltHint]) > 0 {
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
				collector.validateDatabaseCandidate(candidateHex, saltHint, collector.targets)
			}
		}
	}
}

func (collector *candidateCollector) scanDatabasePatterns(data []byte) {
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
		collector.validateDatabaseCandidate(candidate, saltHint, collector.targets)
	}
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
				if len(collector.seenMedia) >= 250_000 {
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

func (collector *candidateCollector) databaseKeys(targets databaseTargets) (map[string]string, int) {
	keys := map[string]string{}
	ambiguous := 0
	for salt, paths := range targets.bySalt {
		candidates := collector.databaseCandidates[strings.ToLower(salt)]
		if len(candidates) != 1 {
			if len(candidates) > 1 {
				ambiguous++
			}
			continue
		}
		var key string
		for candidate := range candidates {
			key = candidate
		}
		for _, path := range paths {
			keys[path] = key
		}
	}
	return keys, ambiguous
}

func (collector *candidateCollector) hasAllDatabaseCandidates() bool {
	if len(collector.targets.bySalt) == 0 {
		return false
	}
	for salt := range collector.targets.bySalt {
		if len(collector.databaseCandidates[strings.ToLower(salt)]) == 0 {
			return false
		}
	}
	return true
}

func (collector *candidateCollector) resolvedMedia(evidence mediaEvidence) *imageKeys {
	if len(collector.mediaCandidates) != 1 || len(evidence.xorCandidates) != 1 {
		return nil
	}
	var aesKey string
	for candidate := range collector.mediaCandidates {
		aesKey = candidate
	}
	var xorKey byte
	for candidate := range evidence.xorCandidates {
		xorKey = candidate
	}
	return &imageKeys{AES: aesKey, XOR: int(xorKey)}
}

// applyScanDiagnostics 把收集器里的计数汇总进诊断结构，并按优先级决定最终图片密钥
// （kvcomm 公式优先于进程内存样本）。各平台的 platformAcquire 收尾完全一致，故收拢在此，
// 避免新增诊断字段时漏改某个平台。
func (collector *candidateCollector) applyScanDiagnostics(diag *diagnostics, keys map[string]string, ambiguous int, derivedMedia *imageKeys, scanMedia mediaEvidence) *imageKeys {
	diag.ScanLimited = diag.ScanLimited || collector.mediaScanLimited || collector.databaseScanLimited
	diag.MatchedDatabaseCount = len(keys)
	diag.AmbiguousDatabaseKeys = ambiguous
	diag.HexPatternCount = collector.hexPatternCount
	diag.RawKeyCandidateCount = collector.rawKeyCandidateCount
	diag.ValidatedCandidateCount = collector.validatedDatabaseCandidateCount
	diag.KeyObjectPatternCount = collector.keyObjectPatternCount
	diag.DereferencedKeyCandidateCount = collector.dereferencedKeyCandidateCount
	diag.PassphraseValidationCount = collector.passphraseValidationCount
	diag.KeyObjectStructuralCount = collector.keyObjectStructuralCount
	diag.KeyObjectCapacity32Count = collector.keyObjectCapacity32Count
	diag.KeyObjectCapacity47Count = collector.keyObjectCapacity47Count
	diag.KeyObjectCapacity63Count = collector.keyObjectCapacity63Count
	diag.KeyObjectOtherCapacityCount = collector.keyObjectOtherCapacityCount
	diag.InternalXORKeyCandidateCount = collector.internalXORKeyCandidateCount
	diag.MediaAESCandidateCount = len(collector.mediaCandidates)
	imageCandidate := derivedMedia
	if imageCandidate != nil {
		diag.MediaCandidateMethod = "kvcomm_formula_v2_sample"
	} else {
		imageCandidate = collector.resolvedMedia(scanMedia)
		if imageCandidate != nil {
			diag.MediaCandidateMethod = "process_memory_v2_sample"
		}
	}
	return imageCandidate
}
