package acquisition

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
)

var (
	sqliteHeader  = []byte("SQLite format 3\x00")
	v1Magic       = []byte{0x07, 0x08, 0x56, 0x31, 0x08, 0x07}
	v2Magic       = []byte{0x07, 0x08, 0x56, 0x32, 0x08, 0x07}
	statisticName = regexp.MustCompile(`(?i)^key_(\d{1,10})_.+\.statistic$`)
	accountSuffix = regexp.MustCompile(`(?i)^(.+)_([0-9a-f]{4,})$`)
)

func cleanWXID(accountName string) string {
	if !strings.HasPrefix(strings.ToLower(accountName), "wxid_") {
		return accountName
	}
	remainder := accountName[len("wxid_"):]
	if index := strings.IndexByte(remainder, '_'); index >= 0 {
		return accountName[:len("wxid_")+index]
	}
	return accountName
}

// accountNameCandidates 返回数量受限的身份候选。部分微信目录布局会在普通用户名后附加
// 实例后缀（例如 "name_ab12"），而 wxid 目录沿用另一种历史格式。这些候选本身均不受信任；
// resolveKVCommMedia 会用全部可用媒体样本验证每个派生密钥，只有通过后才接受。
func accountNameCandidates(accountName string) []string {
	accountName = filepath.Base(filepath.Clean(accountName))
	if accountName == "." || accountName == string(filepath.Separator) || accountName == "" {
		return nil
	}
	values := []string{accountName}
	appendUnique := func(value string) {
		if value == "" {
			return
		}
		for _, existing := range values {
			if strings.EqualFold(existing, value) {
				return
			}
		}
		values = append(values, value)
	}
	appendUnique(cleanWXID(accountName))
	if match := accountSuffix.FindStringSubmatch(accountName); len(match) == 3 {
		appendUnique(match[1])
		appendUnique(cleanWXID(match[1]))
	}
	return values
}

func deriveImageKeysExact(code uint32, accountName string) imageKeys {
	material := strconv.FormatUint(uint64(code), 10) + accountName
	digest := md5.Sum([]byte(material))
	return imageKeys{AES: hex.EncodeToString(digest[:])[:16], XOR: int(code & 0xff)}
}

func deriveImageKeys(code uint32, accountName string) imageKeys {
	return deriveImageKeysExact(code, cleanWXID(accountName))
}

func appendUniquePath(paths []string, value string) []string {
	if value == "" {
		return paths
	}
	cleaned := filepath.Clean(value)
	for _, existing := range paths {
		if strings.EqualFold(filepath.Clean(existing), cleaned) {
			return paths
		}
	}
	return append(paths, cleaned)
}

func macOSKVCommRoots(accountDir, home string) []string {
	var roots []string
	if home != "" {
		roots = appendUniquePath(roots,
			filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "app_data", "net", "kvcomm"))
		roots = appendUniquePath(roots,
			filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Library", "Application Support", "com.tencent.xinWeChat", "xwechat", "net", "kvcomm"))
		roots = appendUniquePath(roots,
			filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Library", "Application Support", "com.tencent.xinWeChat", "net", "kvcomm"))
		roots = appendUniquePath(roots,
			filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "xwechat", "net", "kvcomm"))
	}

	// 账号目录通常是调用方唯一能稳定获得的路径，因此也要由它推导同级的
	// app_data/net/kvcomm 位置。
	normalized := strings.TrimRight(filepath.ToSlash(filepath.Clean(accountDir)), "/")
	if index := strings.Index(normalized, "/xwechat_files"); index >= 0 {
		roots = appendUniquePath(roots, filepath.FromSlash(normalized[:index]+"/app_data/net/kvcomm"))
	}
	if accountDir != "" {
		cursor := filepath.Clean(accountDir)
		for range 8 {
			roots = appendUniquePath(roots, filepath.Join(cursor, "net", "kvcomm"))
			parent := filepath.Dir(cursor)
			if parent == cursor {
				break
			}
			cursor = parent
		}
	}
	return roots
}

func kvcommRoots(accountDir string) []string {
	var roots []string
	appData := strings.TrimSpace(os.Getenv("APPDATA"))
	if appData != "" {
		roots = appendUniquePath(roots, filepath.Join(appData, "Tencent", "xwechat", "net", "kvcomm"))
		roots = appendUniquePath(roots, filepath.Join(appData, "Tencent", "WeChat", "net", "kvcomm"))
	}
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		for _, root := range macOSKVCommRoots(accountDir, home) {
			roots = appendUniquePath(roots, root)
		}
	}
	return roots
}

func kvcommCodes(accountDir string) []uint32 {
	seen := map[uint32]bool{}
	var codes []uint32
	for _, root := range kvcommRoots(accountDir) {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			match := statisticName.FindStringSubmatch(entry.Name())
			if match == nil {
				continue
			}
			value, err := strconv.ParseUint(match[1], 10, 32)
			code := uint32(value)
			if err == nil && code > 0 && !seen[code] {
				seen[code] = true
				codes = append(codes, code)
			}
		}
	}
	return codes
}

func resolveKVCommMedia(accountDir string, evidence mediaEvidence) (*imageKeys, int, int) {
	codes := kvcommCodes(accountDir)
	accountNames := accountNameCandidates(accountDir)
	matches := make([]imageKeys, 0)
	seen := map[string]bool{}
	for _, code := range codes {
		for _, accountName := range accountNames {
			candidate := deriveImageKeysExact(code, accountName)
			if !validateMediaAESBlocks(evidence.V2Blocks, candidate.AES) {
				continue
			}
			if count, found := evidence.XORCandidates[byte(candidate.XOR)]; !found || count == 0 {
				continue
			}
			fingerprint := candidate.AES + ":" + strconv.Itoa(candidate.XOR)
			if seen[fingerprint] {
				continue
			}
			seen[fingerprint] = true
			matches = append(matches, candidate)
		}
	}
	if len(matches) != 1 {
		return nil, len(codes), len(matches)
	}
	return &matches[0], len(codes), 1
}

func selectDominantXOR(evidence mediaEvidence) (mediaEvidence, bool, int, int) {
	selected := mediaEvidence{V2Blocks: evidence.V2Blocks, XORCandidates: map[byte]int{}}
	if len(evidence.XORCandidates) == 0 {
		return selected, false, 0, 0
	}
	var leadingKey byte
	leading, second := 0, 0
	for candidate, count := range evidence.XORCandidates {
		if count > leading {
			second = leading
			leading = count
			leadingKey = candidate
		} else if count > second {
			second = count
		}
	}
	if len(evidence.XORCandidates) > 1 && (leading < 3 || leading < second*4) {
		return selected, false, leading, second
	}
	selected.XORCandidates[leadingKey] = leading
	return selected, true, leading, second
}

func targetsFromCatalog(catalog databaseCatalog, pages []databasePage) databaseTargets {
	targets := databaseTargets{BySalt: map[string][]string{}, Pages: pages, Catalog: catalog}
	for _, database := range catalog.Databases {
		if database.RequiredForKeyCoverage {
			targets.Count++
		}
		if database.Classification == catalogmodel.ClassificationEncrypted && database.Salt != "" {
			targets.BySalt[database.Salt] = append(targets.BySalt[database.Salt], database.RelativePath)
		}
	}
	return targets
}

func TargetsFromCatalog(catalog catalogmodel.Catalog, pages []DatabasePage) Targets {
	return targetsFromCatalog(catalog, pages)
}

// MissingTargets returns the exact required database subset that has not
// already been covered. Existing target pages are referenced as read-only
// evidence and are not copied.
func MissingTargets(targets Targets, existing map[string]string) Targets {
	if len(existing) == 0 {
		return targets
	}
	subset, missingPaths := catalogmodel.MissingRequired(targets.Catalog, existing)
	pages := make([]DatabasePage, 0, len(missingPaths))
	for _, page := range targets.Pages {
		if missingPaths[page.Path] {
			pages = append(pages, page)
		}
	}
	return targetsFromCatalog(subset, pages)
}

// TargetsForProfiles filters a target set to pages whose registered profile is
// eligible for one exact platform recipe.
func TargetsForProfiles(targets Targets, profiles []string) Targets {
	allowedProfiles := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		allowedProfiles[profile] = true
	}
	allowedPaths := map[string]bool{}
	pages := make([]DatabasePage, 0, len(targets.Pages))
	for _, page := range targets.Pages {
		if page.ProfileID == "" && len(allowedProfiles) > 0 || allowedProfiles[page.ProfileID] {
			allowedPaths[page.Path] = true
			pages = append(pages, page)
		}
	}
	subset := catalogmodel.Catalog{
		CatalogID:       targets.Catalog.CatalogID,
		DiscoveryErrors: append([]string(nil), targets.Catalog.DiscoveryErrors...),
	}
	for _, database := range targets.Catalog.Databases {
		if allowedPaths[database.RelativePath] {
			subset.Databases = append(subset.Databases, database)
		}
	}
	return targetsFromCatalog(subset, pages)
}

func DiscoverDatabaseTargets(dbDir string, remaining budget, catalogKey []byte, policy catalogmodel.PlatformPolicy) (Targets, error) {
	if policy.AcquisitionExpired == nil {
		policy.AcquisitionExpired = remaining.Expired
	}
	catalog, pages, err := catalogmodel.Discover(dbDir, catalogKey, policy)
	if err != nil {
		return Targets{}, err
	}
	return targetsFromCatalog(catalog, pages), nil
}

func resolveCaseInsensitive(base string, parts ...string) string {
	current := base
	for _, part := range parts {
		entries, err := os.ReadDir(current)
		if err != nil {
			return ""
		}
		next := ""
		for _, entry := range entries {
			if entry.IsDir() && strings.EqualFold(entry.Name(), part) {
				next = filepath.Join(current, entry.Name())
				break
			}
		}
		if next == "" {
			return ""
		}
		current = next
	}
	return current
}

func mediaRoots(accountDir string) []string {
	candidates := [][]string{
		{"msg", "attach"}, {"cache"}, {"FileStorage", "MsgAttach"},
		{"FileStorage", "Cache"}, {"Message", "Attach"}, {"Message", "Cache"},
	}
	seen := map[string]bool{}
	var roots []string
	for _, parts := range candidates {
		root := resolveCaseInsensitive(accountDir, parts...)
		if root == "" {
			continue
		}
		key := strings.ToLower(filepath.Clean(root))
		if !seen[key] {
			seen[key] = true
			roots = append(roots, root)
		}
	}
	return roots
}

func inferPrefixXOR(ciphertext, signature []byte) (byte, bool) {
	if len(ciphertext) < len(signature) || len(signature) == 0 {
		return 0, false
	}
	key := ciphertext[0] ^ signature[0]
	for index := range signature {
		if ciphertext[index]^key != signature[index] {
			return 0, false
		}
	}
	return key, true
}

func inspectDAT(path string, evidence *mediaEvidence) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	header := make([]byte, 64)
	n, _ := io.ReadFull(file, header)
	header = header[:n]
	if bytes.HasPrefix(header, v2Magic) {
		if len(header) >= 31 && len(evidence.V2Blocks) < 3 {
			var block [16]byte
			copy(block[:], header[15:31])
			evidence.V2Blocks = append(evidence.V2Blocks, block)
		}
		if _, err := file.Seek(-2, io.SeekEnd); err == nil {
			tail := make([]byte, 2)
			if _, err := io.ReadFull(file, tail); err == nil {
				left := tail[0] ^ 0xff
				right := tail[1] ^ 0xd9
				if left == right {
					evidence.XORCandidates[left]++
				}
			}
		}
		return
	}
	if bytes.HasPrefix(header, v1Magic) {
		return
	}
	signatures := [][]byte{
		{0xff, 0xd8, 0xff},
		{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a},
		{'G', 'I', 'F', '8'},
		{'R', 'I', 'F', 'F'},
		{'w', 'x', 'g', 'f'},
	}
	for _, signature := range signatures {
		if key, ok := inferPrefixXOR(header, signature); ok {
			evidence.XORCandidates[key]++
			break
		}
	}
}

func discoverMediaEvidence(accountDir string, budget budget) mediaEvidence {
	evidence := mediaEvidence{XORCandidates: map[byte]int{}}
	inspected := 0
	for _, root := range mediaRoots(accountDir) {
		if budget.Expired() {
			break
		}
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if budget.Expired() {
				return fs.SkipAll
			}
			if walkErr != nil {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			inspected++
			if inspected > 20_000 {
				return filepath.SkipAll
			}
			if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".dat") {
				inspectDAT(path, &evidence)
			}
			return nil
		})
		if inspected > 20_000 {
			break
		}
	}
	return evidence
}

func DiscoverMediaEvidence(accountDir string, remaining budget) MediaEvidence {
	return discoverMediaEvidence(accountDir, remaining)
}

func SelectDominantXOR(evidence MediaEvidence) (MediaEvidence, bool, int, int) {
	return selectDominantXOR(evidence)
}

func ResolveKVCommMedia(accountDir string, evidence MediaEvidence) (*imageKeys, int, int) {
	return resolveKVCommMedia(accountDir, evidence)
}
