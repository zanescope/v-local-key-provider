// Package catalog owns database discovery evidence and stable catalog
// identities. OS-specific file identity and path-safety decisions are injected
// by the process boundary.
package catalog

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Classification string

const (
	ClassificationEncrypted  Classification = "encrypted_eligible"
	ClassificationPlaintext  Classification = "plaintext"
	ClassificationUnreadable Classification = "unreadable"
	ClassificationUnstable   Classification = "unstable"
	ClassificationTruncated  Classification = "truncated"
	MaxDatabaseFiles                        = 4096
)

type Database struct {
	DatabaseID             string         `json:"database_id"`
	RelativePath           string         `json:"relative_path"`
	CanonicalFileID        string         `json:"canonical_file_id"`
	Size                   int64          `json:"size"`
	MTimeNS                int64          `json:"mtime_ns"`
	FirstPageSHA256        string         `json:"first_page_sha256,omitempty"`
	Salt                   string         `json:"-"`
	Classification         Classification `json:"classification"`
	RequiredForKeyCoverage bool           `json:"required_for_key_coverage"`
	ProfileID              string         `json:"profile_id,omitempty"`
	Reason                 string         `json:"reason,omitempty"`
}

type Catalog struct {
	CatalogID       string     `json:"catalog_id"`
	Databases       []Database `json:"databases"`
	DiscoveryErrors []string   `json:"discovery_errors,omitempty"`
}

type Page struct {
	DatabaseID string
	Salt       string
	Path       string
	ProfileID  string
	Data       []byte
}

type PlatformPolicy struct {
	FileIdentity       func(*os.File) (string, error)
	IsLinkOrReparse    func(string, fs.FileMode) (bool, error)
	CanonicalPathKey   func(string) string
	AcquisitionExpired func() bool
}

func (policy PlatformPolicy) validate() error {
	if policy.FileIdentity == nil || policy.IsLinkOrReparse == nil || policy.CanonicalPathKey == nil {
		return errors.New("catalog 平台安全策略不完整")
	}
	return nil
}

func (policy PlatformPolicy) expired() bool {
	return policy.AcquisitionExpired != nil && policy.AcquisitionExpired()
}

func RandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, errors.New("无法生成 catalog 标识密钥")
	}
	return key, nil
}

func HMAC(key []byte, values ...string) string {
	mac := hmac.New(sha256.New, key)
	for _, value := range values {
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(value))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func SafeRelativePath(root, path string) (string, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == "" || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("database_path_outside_root")
	}
	return filepath.Clean(relative), nil
}

func CanonicalFileID(file *os.File, identity func(*os.File) (string, error)) (string, error) {
	if identity == nil {
		return "", errors.New("platform_file_identity_unavailable")
	}
	value, err := identity(file)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:]), nil
}

func firstPage(path string, expected fs.FileInfo, policy PlatformPolicy) ([]byte, fs.FileInfo, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, "", err
	}
	defer file.Close()
	identity, err := CanonicalFileID(file, policy.FileIdentity)
	if err != nil {
		return nil, nil, "", err
	}
	page := make([]byte, 4096)
	read, readErr := io.ReadFull(file, page)
	if readErr != nil && readErr != io.ErrUnexpectedEOF {
		return nil, nil, identity, readErr
	}
	after, err := file.Stat()
	if err != nil {
		return nil, nil, identity, err
	}
	if !os.SameFile(expected, after) || expected.Size() != after.Size() || expected.ModTime() != after.ModTime() {
		return page[:read], after, identity, errors.New("database_changed_during_discovery")
	}
	return page[:read], after, identity, nil
}

func ID(key []byte, databases []Database, discoveryErrors []string) string {
	type identity struct {
		DatabaseID      string         `json:"database_id"`
		CanonicalFileID string         `json:"canonical_file_id"`
		Size            int64          `json:"size"`
		MTimeNS         int64          `json:"mtime_ns"`
		FirstPage       string         `json:"first_page"`
		Classification  Classification `json:"classification"`
		ProfileID       string         `json:"profile_id"`
	}
	values := make([]identity, 0, len(databases))
	for _, database := range databases {
		values = append(values, identity{
			DatabaseID: database.DatabaseID, CanonicalFileID: database.CanonicalFileID,
			Size: database.Size, MTimeNS: database.MTimeNS, FirstPage: database.FirstPageSHA256,
			Classification: database.Classification, ProfileID: database.ProfileID,
		})
	}
	payload, _ := json.Marshal(struct {
		Databases []identity `json:"databases"`
		Errors    []string   `json:"errors,omitempty"`
	}{Databases: values, Errors: discoveryErrors})
	return HMAC(key, string(payload))
}

func Discover(dbDir string, key []byte, policy PlatformPolicy) (Catalog, []Page, error) {
	if len(key) < 16 {
		return Catalog{}, nil, errors.New("catalog 标识密钥无效")
	}
	if err := policy.validate(); err != nil {
		return Catalog{}, nil, err
	}
	root, err := filepath.Abs(dbDir)
	if err != nil {
		return Catalog{}, nil, errors.New("数据库目录绝对路径不可解析")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() {
		return Catalog{}, nil, errors.New("数据库目录不可用")
	}
	unsafeRoot, err := policy.IsLinkOrReparse(root, rootInfo.Mode())
	if err != nil || unsafeRoot {
		return Catalog{}, nil, errors.New("数据库目录不能是链接或 reparse point")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Catalog{}, nil, errors.New("数据库目录真实路径不可解析")
	}
	result := Catalog{}
	pages := []Page{}
	seenPaths := map[string]string{}
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, currentErr error) error {
		if policy.expired() {
			return fs.SkipAll
		}
		if currentErr != nil {
			result.DiscoveryErrors = append(result.DiscoveryErrors, "database_walk_error")
			return nil
		}
		unsafeEntry, safetyErr := policy.IsLinkOrReparse(path, entry.Type())
		if safetyErr != nil {
			result.DiscoveryErrors = append(result.DiscoveryErrors, "database_reparse_check_failed")
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if unsafeEntry {
			result.DiscoveryErrors = append(result.DiscoveryErrors, "database_symlink_rejected")
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".db") {
			return nil
		}
		if len(result.Databases) >= MaxDatabaseFiles {
			result.DiscoveryErrors = append(result.DiscoveryErrors, "database_count_limit_exceeded")
			return fs.SkipAll
		}
		relative, err := SafeRelativePath(root, path)
		if err != nil {
			result.DiscoveryErrors = append(result.DiscoveryErrors, "database_path_outside_root")
			return nil
		}
		pathKey := policy.CanonicalPathKey(relative)
		if previous, duplicate := seenPaths[pathKey]; duplicate && previous != relative {
			result.DiscoveryErrors = append(result.DiscoveryErrors, "database_path_normalization_collision")
		} else {
			seenPaths[pathKey] = relative
		}
		info, err := entry.Info()
		if err != nil {
			result.Databases = append(result.Databases, Database{
				DatabaseID: HMAC(key, relative), RelativePath: relative,
				Classification: ClassificationUnreadable, RequiredForKeyCoverage: true, Reason: "database_stat_failed",
			})
			return nil
		}
		if !info.Mode().IsRegular() {
			result.Databases = append(result.Databases, Database{
				DatabaseID: HMAC(key, relative), RelativePath: relative,
				Size: info.Size(), MTimeNS: info.ModTime().UnixNano(),
				Classification: ClassificationUnreadable, RequiredForKeyCoverage: true, Reason: "database_not_regular",
			})
			return nil
		}
		database := Database{
			DatabaseID: HMAC(key, relative), RelativePath: relative,
			Size: info.Size(), MTimeNS: info.ModTime().UnixNano(),
			Classification: ClassificationUnreadable, RequiredForKeyCoverage: true,
		}
		page, after, identity, readErr := firstPage(path, info, policy)
		database.CanonicalFileID = identity
		if after != nil {
			database.Size = after.Size()
			database.MTimeNS = after.ModTime().UnixNano()
		}
		if len(page) > 0 {
			digest := sha256.Sum256(page)
			database.FirstPageSHA256 = hex.EncodeToString(digest[:])
		}
		switch {
		case readErr != nil && readErr.Error() == "database_changed_during_discovery":
			database.Classification = ClassificationUnstable
			database.Reason = "database_changed_during_discovery"
		case readErr != nil:
			database.Classification = ClassificationUnreadable
			database.Reason = "database_read_failed"
		case len(page) < 16:
			database.Classification = ClassificationTruncated
			database.Reason = "database_first_page_truncated"
		case string(page[:16]) == "SQLite format 3\x00":
			database.Classification = ClassificationPlaintext
			database.RequiredForKeyCoverage = false
		case len(page) < 4096:
			database.Classification = ClassificationTruncated
			database.Reason = "database_first_page_truncated"
		default:
			database.Classification = ClassificationEncrypted
			database.ProfileID = ""
			database.Salt = hex.EncodeToString(page[:16])
			pages = append(pages, Page{
				DatabaseID: database.DatabaseID, Salt: database.Salt, Path: relative,
				ProfileID: database.ProfileID, Data: append([]byte(nil), page...),
			})
		}
		result.Databases = append(result.Databases, database)
		return nil
	})
	if walkErr != nil && walkErr != fs.SkipAll {
		return Catalog{}, nil, walkErr
	}
	if policy.expired() {
		result.DiscoveryErrors = append(result.DiscoveryErrors, "deadline_exhausted")
	}
	sort.Slice(result.Databases, func(left, right int) bool {
		return result.Databases[left].RelativePath < result.Databases[right].RelativePath
	})
	sort.Strings(result.DiscoveryErrors)
	result.CatalogID = ID(key, result.Databases, result.DiscoveryErrors)
	return result, pages, nil
}
