package acquisition

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

// Options 是经验证并由 one-shot 与 session 编排共享的采集输入。CatalogKey 所有权会转移
// 给接收它的 coordinator。
type Options struct {
	AccountDir      string
	DBDir           string
	Database        bool
	Media           bool
	Budget          workbudget.Budget
	HelperMode      bool
	HelperStatus    string
	CatalogKey      []byte
	PlatformSession PlatformSession
	ActionReceipt   string
}

func (options Options) PlatformRequest() PlatformRequest {
	return PlatformRequest{
		AccountDir: options.AccountDir, DBDir: options.DBDir,
		Database: options.Database, Media: options.Media, Budget: options.Budget,
		HelperMode: options.HelperMode, HelperStatus: options.HelperStatus,
		PlatformSession: options.PlatformSession, ActionReceipt: options.ActionReceipt,
	}
}

// OptionPolicy 注入唯一与 OS 相关的路径事实：路径是否为符号链接或 Windows reparse
// point。其余验证均与平台无关，因此归 Options DTO 所有。
type OptionPolicy struct {
	IsLinkOrReparse  func(string, fs.FileMode) (bool, error)
	RandomCatalogKey func() ([]byte, error)
	ClearSensitive   func([]byte)
	Now              func() time.Time
}

func (policy OptionPolicy) normalized() OptionPolicy {
	if policy.RandomCatalogKey == nil {
		policy.RandomCatalogKey = catalogmodel.RandomKey
	}
	if policy.ClearSensitive == nil {
		policy.ClearSensitive = clearBytes
	}
	if policy.Now == nil {
		policy.Now = time.Now
	}
	return policy
}

func parseScopes(scopes []string, options *Options) error {
	seen := map[string]bool{}
	for _, scope := range scopes {
		if seen[scope] {
			return fmt.Errorf("scope %q 不能重复", scope)
		}
		seen[scope] = true
		switch scope {
		case "database":
			options.Database = true
		case "media":
			options.Media = true
		default:
			return fmt.Errorf("不支持的 scope %q", scope)
		}
	}
	return nil
}

func parseCatalogKey(encoded string, policy OptionPolicy) ([]byte, error) {
	if encoded == "" {
		key, err := policy.RandomCatalogKey()
		if err != nil {
			policy.ClearSensitive(key)
			return nil, err
		}
		return key, nil
	}
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		policy.ClearSensitive(key)
		return nil, errors.New("catalog_key 无效")
	}
	return key, nil
}

// ParseOptions 在不依赖 composition root 的情况下验证采集路径、scope、budget 和
// catalog key 所有权。
func ParseOptions(request protocolmodel.AcquireRequest, policy OptionPolicy) (Options, error) {
	policy = policy.normalized()
	if request.AccountDir == "" || request.DBDir == "" || len(request.Scopes) == 0 {
		return Options{}, errors.New("account_dir、db_dir 和 scopes 不能为空")
	}
	if policy.IsLinkOrReparse == nil {
		return Options{}, errors.New("acquisition path policy 缺少 link/reparse 检查")
	}
	accountAbs, err := filepath.Abs(request.AccountDir)
	if err != nil {
		return Options{}, fmt.Errorf("解析账号目录失败：%w", err)
	}
	dbAbs, err := filepath.Abs(request.DBDir)
	if err != nil {
		return Options{}, fmt.Errorf("解析数据库目录失败：%w", err)
	}
	accountLinkInfo, err := os.Lstat(accountAbs)
	accountUnsafe := false
	if err == nil {
		accountUnsafe, err = policy.IsLinkOrReparse(accountAbs, accountLinkInfo.Mode())
	}
	if err != nil || accountUnsafe {
		return Options{}, errors.New("账号目录不能是链接或 reparse point")
	}
	dbLinkInfo, err := os.Lstat(dbAbs)
	dbUnsafe := false
	if err == nil {
		dbUnsafe, err = policy.IsLinkOrReparse(dbAbs, dbLinkInfo.Mode())
	}
	if err != nil || dbUnsafe {
		return Options{}, errors.New("数据库目录不能是链接或 reparse point")
	}
	info, err := os.Stat(accountAbs)
	if err != nil || !info.IsDir() {
		return Options{}, errors.New("账号目录不可用")
	}
	info, err = os.Stat(dbAbs)
	if err != nil || !info.IsDir() {
		return Options{}, errors.New("数据库目录不可用")
	}
	accountReal, err := filepath.EvalSymlinks(accountAbs)
	if err != nil {
		return Options{}, errors.New("账号目录真实路径不可解析")
	}
	dbReal, err := filepath.EvalSymlinks(dbAbs)
	if err != nil {
		return Options{}, errors.New("数据库目录真实路径不可解析")
	}
	relative, err := filepath.Rel(accountReal, dbReal)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return Options{}, errors.New("数据库目录必须位于目标账号目录内")
	}
	options := Options{
		AccountDir: accountReal, DBDir: dbReal,
		Budget: workbudget.New(policy.Now(), request.DeadlineMS),
	}
	if err := parseScopes(request.Scopes, &options); err != nil {
		return Options{}, err
	}
	options.CatalogKey, err = parseCatalogKey(request.CatalogKey, policy)
	if err != nil {
		return Options{}, err
	}
	return options, nil
}

// ParseSecurityPostureOptions 有意跳过全部路径操作。即使重启期间账号路径发生移动，恢复
// 检查仍必须可用，而且绝不能采集凭据。
func ParseSecurityPostureOptions(request protocolmodel.AcquireRequest, policy OptionPolicy) (Options, error) {
	policy = policy.normalized()
	if request.AccountDir == "" || request.DBDir == "" || len(request.Scopes) == 0 {
		return Options{}, errors.New("account_dir、db_dir 和 scopes 不能为空")
	}
	options := Options{Budget: workbudget.New(policy.Now(), request.DeadlineMS)}
	if err := parseScopes(request.Scopes, &options); err != nil {
		return Options{}, err
	}
	if request.CatalogKey != "" {
		key, err := hex.DecodeString(request.CatalogKey)
		if err != nil || len(key) != 32 {
			policy.ClearSensitive(key)
			return Options{}, errors.New("catalog_key 无效")
		}
		options.CatalogKey = key
	}
	return options, nil
}
