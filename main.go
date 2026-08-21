package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// v1 没有时限字段，行为与历史一致（不自我收敛）；v2 要求调用方给出 deadline_ms。
// 两个版本同时接受，响应按请求使用的版本回显。
const protocolName = "v-local-key-provider/v1"
const protocolNameV2 = "v-local-key-provider/v2"
const maxRequestBytes = 1024 * 1024

var version = "0.1.0-dev.0"

type acquireOptions struct {
	accountDir   string
	dbDir        string
	database     bool
	media        bool
	budget       budget
	helperMode   bool
	helperStatus string
}

type acquireRequest struct {
	Protocol   string   `json:"protocol"`
	RequestID  string   `json:"request_id"`
	Action     string   `json:"action"`
	AccountDir string   `json:"account_dir"`
	DBDir      string   `json:"db_dir"`
	Scopes     []string `json:"scopes"`
	DeadlineMS *int64   `json:"deadline_ms,omitempty"`
}

type imageKeys struct {
	AES string `json:"aes"`
	XOR int    `json:"xor"`
}

type diagnostics struct {
	Platform                      string `json:"platform"`
	WeChatVersion                 string `json:"wechat_version,omitempty"`
	ProcessArchitecture           string `json:"process_architecture,omitempty"`
	ProcessAccessStatus           string `json:"process_access_status,omitempty"`
	ProcessAccessError            string `json:"process_access_error,omitempty"`
	HelperStatus                  string `json:"helper_status,omitempty"`
	HookTargetFound               int    `json:"hook_target_found"`
	HookInstalled                 bool   `json:"hook_installed"`
	HookTimeout                   bool   `json:"hook_timeout"`
	HookTriggerRequired           bool   `json:"hook_trigger_required"`
	HookRestartRequired           bool   `json:"hook_restart_required"`
	HookCaptureCount              int    `json:"hook_capture_count"`
	DynamicHookUsed               bool   `json:"dynamic_hook_used"`
	StaticScanFallback            bool   `json:"static_scan_fallback"`
	VersionSupport                string `json:"version_support,omitempty"`
	ProcessCount                  int    `json:"process_count"`
	OpenedProcessCount            int    `json:"opened_process_count"`
	AccessDeniedCount             int    `json:"access_denied_count"`
	DatabaseCount                 int    `json:"database_count"`
	MatchedDatabaseCount          int    `json:"matched_database_count"`
	AmbiguousDatabaseKeys         int    `json:"ambiguous_database_keys"`
	HexPatternCount               int    `json:"hex_pattern_count"`
	RawKeyCandidateCount          int    `json:"raw_key_candidate_count"`
	ValidatedCandidateCount       int    `json:"validated_database_candidate_count"`
	KeyObjectPatternCount         int    `json:"key_object_pattern_count"`
	DereferencedKeyCandidateCount int    `json:"dereferenced_key_candidate_count"`
	PassphraseValidationCount     int    `json:"passphrase_validation_count"`
	KeyObjectStructuralCount      int    `json:"key_object_structural_count"`
	KeyObjectCapacity32Count      int    `json:"key_object_capacity_32_count"`
	KeyObjectCapacity47Count      int    `json:"key_object_capacity_47_count"`
	KeyObjectCapacity63Count      int    `json:"key_object_capacity_63_count"`
	KeyObjectOtherCapacityCount   int    `json:"key_object_other_capacity_count"`
	InternalXORKeyCandidateCount  int    `json:"internal_xor_key_candidate_count"`
	V2SampleCount                 int    `json:"v2_sample_count"`
	XORSampleCount                int    `json:"xor_sample_count"`
	XORDistinctCandidateCount     int    `json:"xor_distinct_candidate_count"`
	XORLeadingSampleCount         int    `json:"xor_leading_sample_count"`
	XORSecondSampleCount          int    `json:"xor_second_sample_count"`
	MediaAESCandidateCount        int    `json:"media_aes_candidate_count"`
	KVCommCodeCandidateCount      int    `json:"kvcomm_code_candidate_count"`
	KVCommVerifiedCandidateCount  int    `json:"kvcomm_verified_candidate_count"`
	MediaCandidateMethod          string `json:"media_candidate_method,omitempty"`
	ProcessDiscoveryMethod        string `json:"process_discovery_method,omitempty"`
	ScannedBytes                  uint64 `json:"scanned_bytes"`
	ScanLimited                   bool   `json:"scan_limited"`
	// BudgetExhausted 为真表示时限用尽而提前收工，database_keys 可能不完整。
	BudgetExhausted bool  `json:"budget_exhausted"`
	ElapsedMS       int64 `json:"elapsed_ms"`
}

type response struct {
	Protocol     string            `json:"protocol"`
	RequestID    string            `json:"request_id"`
	DatabaseKeys map[string]string `json:"database_keys,omitempty"`
	ImageKeys    *imageKeys        `json:"image_keys,omitempty"`
	Diagnostics  diagnostics       `json:"diagnostics"`
}

func readRequest(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(reader, maxRequestBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, errors.New("读取请求失败")
	}
	if len(data) == 0 || len(data) > maxRequestBytes {
		return nil, errors.New("请求为空或超过安全上限")
	}
	return data, nil
}

func decodeRequestData(data []byte) (acquireRequest, error) {
	var request acquireRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return acquireRequest{}, errors.New("请求不是有效的 JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return acquireRequest{}, errors.New("请求只能包含一个 JSON 对象")
	}
	switch request.Protocol {
	case protocolName:
		if request.DeadlineMS != nil {
			return acquireRequest{}, fmt.Errorf("%s 不支持 deadline_ms，请改用 %s", protocolName, protocolNameV2)
		}
	case protocolNameV2:
		if request.DeadlineMS == nil {
			return acquireRequest{}, fmt.Errorf("%s 必须提供 deadline_ms", protocolNameV2)
		}
		if *request.DeadlineMS <= 0 || *request.DeadlineMS > maxBudgetMilliseconds {
			return acquireRequest{}, errors.New("deadline_ms 超出允许范围")
		}
	default:
		return acquireRequest{}, fmt.Errorf("协议不匹配：收到 %q，需要 %q 或 %q",
			request.Protocol, protocolName, protocolNameV2)
	}
	if request.Action != "acquire" {
		return acquireRequest{}, errors.New("不支持的操作")
	}
	if request.RequestID == "" || len(request.RequestID) > 128 {
		return acquireRequest{}, errors.New("request_id 无效")
	}
	return request, nil
}

func decodeRequest(reader io.Reader) (acquireRequest, error) {
	data, err := readRequest(reader)
	if err != nil {
		return acquireRequest{}, err
	}
	return decodeRequestData(data)
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
	info, err := os.Stat(accountAbs)
	if err != nil || !info.IsDir() {
		return acquireOptions{}, errors.New("账号目录不可用")
	}
	info, err = os.Stat(dbAbs)
	if err != nil || !info.IsDir() {
		return acquireOptions{}, errors.New("数据库目录不可用")
	}
	options := acquireOptions{accountDir: accountAbs, dbDir: dbAbs, budget: unlimitedBudget()}
	if request.DeadlineMS != nil {
		options.budget = newBudget(time.Now(), *request.DeadlineMS)
	}
	for _, scope := range request.Scopes {
		switch scope {
		case "database":
			options.database = true
		case "image":
			options.media = true
		default:
			return acquireOptions{}, fmt.Errorf("不支持的 scope %q", scope)
		}
	}
	return options, nil
}

func runAcquire(options acquireOptions) (response, error) {
	started := time.Now()
	targets := databaseTargets{}
	var media mediaEvidence
	var err error
	if options.database {
		targets, err = discoverDatabaseTargets(options.dbDir, options.budget)
		if err != nil {
			return response{}, err
		}
		if len(targets.bySalt) == 0 && !options.budget.expired() {
			return response{}, errors.New("没有找到加密数据库盐值")
		}
	}
	if options.media {
		media = discoverMediaEvidence(options.accountDir, options.budget)
	}
	result, diag, err := platformAcquire(targets, media, options)
	if err != nil {
		return response{}, err
	}
	diag.ElapsedMS = time.Since(started).Milliseconds()
	diag.BudgetExhausted = options.budget.expired()
	if diag.BudgetExhausted && len(result.DatabaseKeys) == 0 && result.ImageKeys == nil {
		diag.ProcessAccessStatus = "deadline_exhausted"
	}
	result.Diagnostics = diag
	return result, nil
}

func writeError(err error, code int) {
	fmt.Fprintf(os.Stderr, "v-local-key-provider: %v\n", err)
	os.Exit(code)
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Fprintln(os.Stdout, version)
		return
	}
	if len(os.Args) != 2 || (os.Args[1] != "acquire" && os.Args[1] != "helper-acquire") {
		writeError(errors.New("用法：v-local-key-provider acquire < request.json"), 2)
	}
	payload, err := readRequest(os.Stdin)
	if err != nil {
		writeError(err, 2)
	}
	request, err := decodeRequestData(payload)
	if err != nil {
		writeError(err, 2)
	}
	helperMode := os.Args[1] == "helper-acquire"
	helperStatus := ""
	options, err := optionsFromRequest(request)
	if err != nil {
		writeError(err, 2)
	}
	if !helperMode {
		delegated, status := delegateToPlatformHelper(payload, options.budget)
		if delegated {
			return
		}
		helperStatus = status
	}
	options.helperMode = helperMode
	options.helperStatus = helperStatus
	result, err := runAcquire(options)
	if err != nil {
		writeError(err, 3)
	}
	result.Protocol = request.Protocol
	result.RequestID = request.RequestID
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		writeError(errors.New("编码协议响应失败"), 4)
	}
}
