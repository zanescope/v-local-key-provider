package main

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
)

var (
	sqliteHeader  = []byte("SQLite format 3\x00")
	v1Magic       = []byte{0x07, 0x08, 0x56, 0x31, 0x08, 0x07}
	v2Magic       = []byte{0x07, 0x08, 0x56, 0x32, 0x08, 0x07}
	statisticName = regexp.MustCompile(`(?i)^key_(\d{1,10})_.+\.statistic$`)
)

type databaseTargets struct {
	bySalt map[string][]string
	pages  []databasePage
	count  int
}

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

func deriveImageKeys(code uint32, accountName string) imageKeys {
	material := strconv.FormatUint(uint64(code), 10) + cleanWXID(accountName)
	digest := md5.Sum([]byte(material))
	return imageKeys{AES: hex.EncodeToString(digest[:])[:16], XOR: int(code & 0xff)}
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

	// The account directory is often the only stable path available to the
	// caller. Derive sibling app_data/net/kvcomm locations from it as well.
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
	accountName := filepath.Base(filepath.Clean(accountDir))
	var matches []imageKeys
	for _, code := range codes {
		candidate := deriveImageKeys(code, accountName)
		if !validateMediaAESBlocks(evidence.v2Blocks, candidate.AES) {
			continue
		}
		if count, found := evidence.xorCandidates[byte(candidate.XOR)]; !found || count == 0 {
			continue
		}
		matches = append(matches, candidate)
	}
	if len(matches) != 1 {
		return nil, len(codes), len(matches)
	}
	return &matches[0], len(codes), 1
}

type databasePage struct {
	salt string
	path string
	data []byte
}

type mediaEvidence struct {
	v2Blocks      [][16]byte
	xorCandidates map[byte]int
}

func selectDominantXOR(evidence mediaEvidence) (mediaEvidence, bool, int, int) {
	selected := mediaEvidence{v2Blocks: evidence.v2Blocks, xorCandidates: map[byte]int{}}
	if len(evidence.xorCandidates) == 0 {
		return selected, false, 0, 0
	}
	var leadingKey byte
	leading, second := 0, 0
	for candidate, count := range evidence.xorCandidates {
		if count > leading {
			second = leading
			leading = count
			leadingKey = candidate
		} else if count > second {
			second = count
		}
	}
	if len(evidence.xorCandidates) > 1 && (leading < 3 || leading < second*4) {
		return selected, false, leading, second
	}
	selected.xorCandidates[leadingKey] = leading
	return selected, true, leading, second
}

func discoverDatabaseTargets(dbDir string, budget budget) (databaseTargets, error) {
	targets := databaseTargets{bySalt: map[string][]string{}}
	err := filepath.WalkDir(dbDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if budget.expired() {
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
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".db") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		page := make([]byte, 4096)
		read, readErr := io.ReadFull(file, page)
		file.Close()
		if read < 16 || (readErr != nil && readErr != io.ErrUnexpectedEOF) || bytes.Equal(page[:16], sqliteHeader) {
			return nil
		}
		relative, err := filepath.Rel(dbDir, path)
		if err != nil {
			return nil
		}
		salt := hex.EncodeToString(page[:16])
		targets.bySalt[salt] = append(targets.bySalt[salt], relative)
		if read == len(page) {
			targets.pages = append(targets.pages, databasePage{salt: salt, path: relative, data: page})
		}
		targets.count++
		return nil
	})
	if err == fs.SkipAll {
		err = nil
	}
	return targets, err
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
		if len(header) >= 31 && len(evidence.v2Blocks) < 3 {
			var block [16]byte
			copy(block[:], header[15:31])
			evidence.v2Blocks = append(evidence.v2Blocks, block)
		}
		if _, err := file.Seek(-2, io.SeekEnd); err == nil {
			tail := make([]byte, 2)
			if _, err := io.ReadFull(file, tail); err == nil {
				left := tail[0] ^ 0xff
				right := tail[1] ^ 0xd9
				if left == right {
					evidence.xorCandidates[left]++
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
			evidence.xorCandidates[key]++
			break
		}
	}
}

func discoverMediaEvidence(accountDir string, budget budget) mediaEvidence {
	evidence := mediaEvidence{xorCandidates: map[byte]int{}}
	inspected := 0
	for _, root := range mediaRoots(accountDir) {
		if budget.expired() {
			break
		}
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if budget.expired() {
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
