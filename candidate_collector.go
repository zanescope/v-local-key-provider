package provider

import "strings"

const (
	minDatabaseHexLength    = 64
	maxDatabaseHexLength    = 192
	maxCandidateCount       = 512
	maxBinaryCandidateCount = 512
	maxMediaCandidateCount  = 512
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

type globalPassphraseEvidence struct {
	secret               []byte
	paths                map[string]bool
	sources              map[string]bool
	completeCallEvidence bool
}

type databaseCandidateInfo struct {
	profileID string
	origins   map[string]bool
}

// candidateScanCounters is the single merge boundary for process-isolated scan
// observations. Keeping the list here prevents each caller from reimplementing a
// subtly different field-by-field aggregation policy.
type candidateScanCounters struct {
	mediaScanLimited                bool
	databaseScanLimited             bool
	kdfBudgetExhausted              bool
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
	validatorConflictCount          int
	candidateObservationCount       int
	passphraseObservationCount      int
}

func (counters *candidateScanCounters) merge(other candidateScanCounters) {
	counters.mediaScanLimited = counters.mediaScanLimited || other.mediaScanLimited
	counters.databaseScanLimited = counters.databaseScanLimited || other.databaseScanLimited
	counters.kdfBudgetExhausted = counters.kdfBudgetExhausted || other.kdfBudgetExhausted
	counters.hexPatternCount += other.hexPatternCount
	counters.rawKeyCandidateCount += other.rawKeyCandidateCount
	counters.validatedDatabaseCandidateCount += other.validatedDatabaseCandidateCount
	counters.keyObjectPatternCount += other.keyObjectPatternCount
	counters.dereferencedKeyCandidateCount += other.dereferencedKeyCandidateCount
	counters.passphraseValidationCount += other.passphraseValidationCount
	counters.keyObjectStructuralCount += other.keyObjectStructuralCount
	counters.keyObjectCapacity32Count += other.keyObjectCapacity32Count
	counters.keyObjectCapacity47Count += other.keyObjectCapacity47Count
	counters.keyObjectCapacity63Count += other.keyObjectCapacity63Count
	counters.keyObjectOtherCapacityCount += other.keyObjectOtherCapacityCount
	counters.internalXORKeyCandidateCount += other.internalXORKeyCandidateCount
	counters.validatorConflictCount += other.validatorConflictCount
	counters.candidateObservationCount += other.candidateObservationCount
	counters.passphraseObservationCount += other.passphraseObservationCount
}

type candidateCollector struct {
	processInstanceID        string
	validationBudget         budget
	targets                  databaseTargets
	salts                    map[string]bool
	databaseCandidates       map[string]map[string]*databaseCandidateInfo
	mediaBlocks              [][16]byte
	seenMedia                map[string]bool
	mediaCandidates          map[string]bool
	seenDatabase             map[string]bool
	binaryCandidates         [][]byte
	binaryFallbackCandidates [][]byte
	internalXORKeys          [][]byte
	seenInternalXORKeys      map[string]bool
	globalPassphrases        map[string]*globalPassphraseEvidence
	candidateScanCounters
}

func newCandidateCollector(targets databaseTargets, media mediaEvidence, budgets ...budget) *candidateCollector {
	validationBudget := unlimitedBudget()
	if len(budgets) > 0 {
		validationBudget = budgets[0]
	}
	collector := &candidateCollector{
		validationBudget:    validationBudget,
		targets:             targets,
		salts:               map[string]bool{},
		databaseCandidates:  map[string]map[string]*databaseCandidateInfo{},
		mediaBlocks:         media.v2Blocks,
		seenMedia:           map[string]bool{},
		mediaCandidates:     map[string]bool{},
		seenDatabase:        map[string]bool{},
		seenInternalXORKeys: map[string]bool{},
		globalPassphrases:   map[string]*globalPassphraseEvidence{},
	}
	for salt := range targets.bySalt {
		collector.salts[strings.ToLower(salt)] = true
	}
	return collector
}

func (collector *candidateCollector) clearSensitiveBuffers() {
	if collector == nil {
		return
	}
	for _, values := range [][][]byte{collector.binaryCandidates, collector.binaryFallbackCandidates, collector.internalXORKeys} {
		for _, value := range values {
			zeroBytes(value)
		}
	}
	for _, evidence := range collector.globalPassphrases {
		zeroBytes(evidence.secret)
		evidence.secret = nil
	}
	collector.binaryCandidates = nil
	collector.binaryFallbackCandidates = nil
	collector.internalXORKeys = nil
}

// mergeValidatedFrom combines only target-bound results from an isolated
// process collector. Raw memory candidates and unresolved passphrase buffers
// deliberately stay behind so candidates from different process instances are
// never combined before cryptographic validation.
func (collector *candidateCollector) mergeValidatedFrom(other *candidateCollector) {
	if collector == nil || other == nil {
		return
	}
	for path, candidates := range other.databaseCandidates {
		for key, information := range candidates {
			current, _ := collector.ensureDatabaseCandidate(path, key, information.profileID)
			for origin := range information.origins {
				current.origins[origin] = true
			}
		}
	}
	for id, evidence := range other.globalPassphrases {
		current := collector.globalPassphrases[id]
		if current == nil {
			current = &globalPassphraseEvidence{
				secret: cloneSensitiveBytes(evidence.secret), paths: map[string]bool{}, sources: map[string]bool{},
			}
			collector.globalPassphrases[id] = current
		}
		current.completeCallEvidence = current.completeCallEvidence || evidence.completeCallEvidence
		for path := range evidence.paths {
			current.paths[path] = true
		}
		for source := range evidence.sources {
			current.sources[source] = true
		}
	}
	for candidate := range other.mediaCandidates {
		collector.mediaCandidates[candidate] = true
	}
	// seenDatabase/seenMedia contain unresolved process-memory values and must
	// never cross a process isolation boundary. Only aggregate their counts.
	observations := other.candidateScanCounters
	observations.candidateObservationCount += len(other.seenDatabase)
	observations.passphraseObservationCount += len(other.binaryCandidates) + len(other.binaryFallbackCandidates)
	collector.candidateScanCounters.merge(observations)
}

func (collector *candidateCollector) databaseKeys(_ databaseTargets) (map[string]string, int) {
	keys := map[string]string{}
	ambiguous := 0
	collector.validatorConflictCount = 0
	seenPaths := map[string]bool{}
	for _, target := range collector.targets.pages {
		if seenPaths[target.path] {
			continue
		}
		seenPaths[target.path] = true
		candidates := collector.databaseCandidates[target.path]
		if len(candidates) != 1 {
			if len(candidates) > 1 {
				ambiguous++
				// Two distinct effective keys cannot both authenticate the same
				// physical first page. Treat this as validator/file-drift failure
				// regardless of whether the keys were accepted through the same
				// profile or two different registered profiles.
				collector.validatorConflictCount++
			}
			continue
		}
		var key string
		for candidate := range candidates {
			key = candidate
		}
		keys[target.path] = key
	}
	return keys, ambiguous
}

func (collector *candidateCollector) profilesForKeys(keys map[string]string) map[string]string {
	profiles := map[string]string{}
	for path, key := range keys {
		if information := collector.databaseCandidates[path][key]; information != nil && information.profileID != "" {
			profiles[path] = information.profileID
		}
	}
	return profiles
}

func (collector *candidateCollector) hasAllDatabaseCandidates() bool {
	if collector.targets.count == 0 || len(collector.targets.pages) != collector.targets.count {
		return false
	}
	for _, target := range collector.targets.pages {
		if len(collector.databaseCandidates[target.path]) == 0 {
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
	diag.ValidatorConflictCount = collector.validatorConflictCount
	diag.CandidateCount = len(collector.seenDatabase) + collector.candidateObservationCount
	diag.PassphraseCandidateCount = len(collector.binaryCandidates) + len(collector.binaryFallbackCandidates) + collector.passphraseObservationCount
	diag.KDFBudgetExhausted = collector.kdfBudgetExhausted
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
