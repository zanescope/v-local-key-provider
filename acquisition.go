package provider

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type acquireOptions struct {
	accountDir      string
	dbDir           string
	database        bool
	media           bool
	budget          budget
	helperMode      bool
	helperStatus    string
	catalogKey      []byte
	platformSession acquisitionPlatformSession
	actionReceipt   string
}

func optionsFromRequest(request acquireRequest) (acquireOptions, error) {
	if request.AccountDir == "" || request.DBDir == "" || len(request.Scopes) == 0 {
		return acquireOptions{}, errors.New("account_dir、db_dir 和 scopes 不能为空")
	}
	accountAbs, err := filepath.Abs(request.AccountDir)
	if err != nil {
		return acquireOptions{}, fmt.Errorf("解析账号目录失败：%w", err)
	}
	dbAbs, err := filepath.Abs(request.DBDir)
	if err != nil {
		return acquireOptions{}, fmt.Errorf("解析数据库目录失败：%w", err)
	}
	accountLinkInfo, err := os.Lstat(accountAbs)
	accountUnsafe := false
	if err == nil {
		accountUnsafe, err = pathIsLinkOrReparse(accountAbs, accountLinkInfo.Mode())
	}
	if err != nil || accountUnsafe {
		return acquireOptions{}, errors.New("账号目录不能是链接或 reparse point")
	}
	dbLinkInfo, err := os.Lstat(dbAbs)
	dbUnsafe := false
	if err == nil {
		dbUnsafe, err = pathIsLinkOrReparse(dbAbs, dbLinkInfo.Mode())
	}
	if err != nil || dbUnsafe {
		return acquireOptions{}, errors.New("数据库目录不能是链接或 reparse point")
	}
	info, err := os.Stat(accountAbs)
	if err != nil || !info.IsDir() {
		return acquireOptions{}, errors.New("账号目录不可用")
	}
	info, err = os.Stat(dbAbs)
	if err != nil || !info.IsDir() {
		return acquireOptions{}, errors.New("数据库目录不可用")
	}
	accountReal, err := filepath.EvalSymlinks(accountAbs)
	if err != nil {
		return acquireOptions{}, errors.New("账号目录真实路径不可解析")
	}
	dbReal, err := filepath.EvalSymlinks(dbAbs)
	if err != nil {
		return acquireOptions{}, errors.New("数据库目录真实路径不可解析")
	}
	relative, err := filepath.Rel(accountReal, dbReal)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return acquireOptions{}, errors.New("数据库目录必须位于目标账号目录内")
	}
	options := acquireOptions{
		accountDir: accountReal, dbDir: dbReal,
		budget: newBudget(time.Now(), request.DeadlineMS),
	}
	seenScopes := map[string]bool{}
	for _, scope := range request.Scopes {
		if seenScopes[scope] {
			return acquireOptions{}, fmt.Errorf("scope %q 不能重复", scope)
		}
		seenScopes[scope] = true
		switch scope {
		case "database":
			options.database = true
		case "media":
			options.media = true
		default:
			return acquireOptions{}, fmt.Errorf("不支持的 scope %q", scope)
		}
	}
	var catalogKey []byte
	if request.CatalogKey != "" {
		catalogKey, err = hex.DecodeString(request.CatalogKey)
		if err != nil || len(catalogKey) != 32 {
			return acquireOptions{}, errors.New("catalog_key 无效")
		}
	} else {
		catalogKey, err = randomCatalogKey()
		if err != nil {
			return acquireOptions{}, err
		}
	}
	options.catalogKey = catalogKey
	return options, nil
}

func securityPostureRevalidationOptions(request acquireRequest) (acquireOptions, error) {
	// A restoration check is deliberately independent of acquisition paths: the
	// account or database directory may have moved or disappeared while the user
	// was rebooting. Keep their non-empty correlation values in the request, but
	// do not stat, resolve, scan, or otherwise use them for this posture-only RPC.
	if request.AccountDir == "" || request.DBDir == "" || len(request.Scopes) == 0 {
		return acquireOptions{}, errors.New("account_dir、db_dir 和 scopes 不能为空")
	}
	options := acquireOptions{budget: newBudget(time.Now(), request.DeadlineMS)}
	seenScopes := map[string]bool{}
	for _, scope := range request.Scopes {
		if seenScopes[scope] {
			return acquireOptions{}, fmt.Errorf("scope %q 不能重复", scope)
		}
		seenScopes[scope] = true
		switch scope {
		case "database":
			options.database = true
		case "media":
			options.media = true
		default:
			return acquireOptions{}, fmt.Errorf("不支持的 scope %q", scope)
		}
	}
	if request.CatalogKey != "" {
		catalogKey, err := hex.DecodeString(request.CatalogKey)
		if err != nil || len(catalogKey) != 32 {
			zeroBytes(catalogKey)
			return acquireOptions{}, errors.New("catalog_key 无效")
		}
		options.catalogKey = catalogKey
	}
	return options, nil
}

func runAcquire(options acquireOptions) (response, error) {
	defer func() { zeroBytes(options.catalogKey) }()
	started := time.Now()
	targets := databaseTargets{}
	var media mediaEvidence
	var err error
	phaseTimings := map[string]int64{}
	if options.database {
		if len(options.catalogKey) == 0 {
			options.catalogKey, err = randomCatalogKey()
			if err != nil {
				return response{}, err
			}
		}
		phaseStarted := time.Now()
		targets, err = discoverDatabaseTargetsWithKey(options.dbDir, options.budget, options.catalogKey)
		phaseTimings["target_database_discovery"] = time.Since(phaseStarted).Milliseconds()
		if err != nil {
			return response{}, err
		}
	}
	if options.media {
		phaseStarted := time.Now()
		media = discoverMediaEvidence(options.accountDir, options.budget)
		phaseTimings["media_discovery"] = time.Since(phaseStarted).Milliseconds()
	}
	result, err := runPreparedAcquire(options, targets, media, started)
	if result.Diagnostics.PhaseTimingsMS == nil {
		result.Diagnostics.PhaseTimingsMS = map[string]int64{}
	}
	for phase, elapsed := range phaseTimings {
		result.Diagnostics.PhaseTimingsMS[phase] = elapsed
	}
	return result, err
}

func runPreparedAcquire(options acquireOptions, targets databaseTargets, media mediaEvidence, started time.Time) (response, error) {
	phaseStarted := time.Now()
	result, diag, err := platformDriver.Acquire(targets, media, platformRequestFromOptions(options))
	if err != nil {
		return response{}, err
	}
	if diag.PhaseTimingsMS == nil {
		diag.PhaseTimingsMS = map[string]int64{}
	}
	diag.PhaseTimingsMS["primary_acquire"] = time.Since(phaseStarted).Milliseconds()
	diag.PhaseTimingsMS["total"] = time.Since(started).Milliseconds()
	diag.ElapsedMS = time.Since(started).Milliseconds()
	diag.BudgetExhausted = options.budget.expired()
	finalizeDiagnostics(&diag, targets, result, options)
	result.CatalogID = targets.Catalog.CatalogID
	result.CatalogEntries = append([]catalogDatabase(nil), targets.Catalog.Databases...)
	if result.DatabaseCredential != nil {
		result.DatabaseCredential.AccountBindingID = catalogHMAC(options.catalogKey, "account", options.accountDir)
	}
	result.Profiles = profileSummaries()
	result.Diagnostics = diag
	return result, nil
}
