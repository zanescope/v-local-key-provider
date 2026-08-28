// Package session 持有工作流 receipt 验证、重试限制和响应合并。平台采集仍位于命令边界的
// callback 之后；共享响应发布策略由 protocol 持有。
package session

import (
	"errors"
	"sort"
	"strings"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

type ReceiptState struct {
	CatalogID         string
	ProcessInstanceID string
	LastRoute         string
	LastActionStage   string
}

func ReceiptFingerprint(receipt *protocolmodel.ActionReceipt, state ReceiptState, currentProcessInstanceID string) (string, error) {
	if receipt == nil {
		return "", nil
	}
	allowed := map[string]bool{
		"trigger_database": true, "restart_wechat": true, "relogin_wechat": true,
		"switch_to_target_account": true,
	}
	if !allowed[receipt.Action] || !receipt.UserConfirmed {
		return "", errors.New("action_receipt 无效或缺少用户确认")
	}
	if state.LastActionStage == "" || receipt.Action != state.LastActionStage {
		return "", errors.New("action_receipt 与 Provider 待处理动作不匹配")
	}
	if receipt.ProcessInstanceID == "" || receipt.ProcessInstanceID != state.ProcessInstanceID {
		return "", errors.New("action_receipt 未绑定 Provider 记录的原进程实例")
	}
	if receipt.Route != "" && receipt.Route != state.LastRoute {
		return "", errors.New("action_receipt route 与 Provider 状态不匹配")
	}
	if receipt.ActionStage != "" && receipt.ActionStage != state.LastActionStage {
		return "", errors.New("action_receipt stage 与 Provider 状态不匹配")
	}
	processChanged := currentProcessInstanceID != state.ProcessInstanceID
	expectedTransition := "same_process"
	if processChanged {
		expectedTransition = "process_changed"
	}
	claimedTransition := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(receipt.ObservedProcessTransition)), "-", "_")
	if claimedTransition != "" && claimedTransition != expectedTransition {
		return "", errors.New("action_receipt 的进程变化声明与机器观测不一致")
	}
	switch receipt.Action {
	case "trigger_database":
		if processChanged {
			return "", errors.New("只读触发动作期间目标进程实例发生变化，需要重新 prepare")
		}
	case "restart_wechat":
		if !processChanged {
			return "", errors.New("未观测到微信进程实例变化，不能接受 restart 回执")
		}
	case "relogin_wechat", "switch_to_target_account":
		// receipt 只授权重新收集，不能证明账号绑定，也不能提升 session_account_status。
	}
	return strings.Join([]string{
		receipt.Action, currentProcessInstanceID, state.CatalogID, state.LastRoute, state.LastActionStage,
	}, "\x00"), nil
}

func SameScopes(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

// MissingCatalog 返回尚未覆盖的精确必需数据库子集。page 证据由调用方主动筛选，因此该
// 策略无法保留或复制敏感 page buffer。
func MissingCatalog(catalog catalogmodel.Catalog, existing map[string]string) (catalogmodel.Catalog, map[string]bool) {
	return catalogmodel.MissingRequired(catalog, existing)
}

func AppendUniqueStrings(values []string, additions ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	return values
}

func CloneDatabaseCredential(value *credentialmodel.DatabaseCredential) *credentialmodel.DatabaseCredential {
	if value == nil {
		return nil
	}
	clone := *value
	clone.Roots = append([]credentialmodel.Root(nil), value.Roots...)
	for index := range clone.Roots {
		clone.Roots[index].VerifiedDatabaseIDs = append([]string(nil), value.Roots[index].VerifiedDatabaseIDs...)
		clone.Roots[index].SourceEvidence = append([]string(nil), value.Roots[index].SourceEvidence...)
		clone.Roots[index].ProcessInstanceIDs = append([]string(nil), value.Roots[index].ProcessInstanceIDs...)
	}
	clone.Overrides = map[string]credentialmodel.Override{}
	for id, override := range value.Overrides {
		override.SourceEvidence = append([]string(nil), override.SourceEvidence...)
		override.ProcessInstanceIDs = append([]string(nil), override.ProcessInstanceIDs...)
		clone.Overrides[id] = override
	}
	return &clone
}

func MergeDatabaseCredentials(existing, next *credentialmodel.DatabaseCredential) *credentialmodel.DatabaseCredential {
	merged := CloneDatabaseCredential(existing)
	if merged == nil {
		return CloneDatabaseCredential(next)
	}
	if next == nil {
		return merged
	}
	for _, root := range next.Roots {
		matched := false
		for index := range merged.Roots {
			current := &merged.Roots[index]
			if current.Kind != root.Kind || current.ProfileID != root.ProfileID || current.Secret != root.Secret {
				continue
			}
			current.VerifiedCatalogID = root.VerifiedCatalogID
			current.VerifiedDatabaseIDs = AppendUniqueStrings(current.VerifiedDatabaseIDs, root.VerifiedDatabaseIDs...)
			sort.Strings(current.VerifiedDatabaseIDs)
			current.SourceEvidence = AppendUniqueStrings(current.SourceEvidence, root.SourceEvidence...)
			current.ProcessInstanceIDs = AppendUniqueStrings(current.ProcessInstanceIDs, root.ProcessInstanceIDs...)
			sort.Strings(current.ProcessInstanceIDs)
			matched = true
			break
		}
		if !matched {
			merged.Roots = append(merged.Roots, root)
		}
	}
	if merged.Overrides == nil {
		merged.Overrides = map[string]credentialmodel.Override{}
	}
	for id, override := range next.Overrides {
		if current, found := merged.Overrides[id]; found && current.Kind == override.Kind &&
			current.ProfileID == override.ProfileID && current.Secret == override.Secret && current.RelativePath == override.RelativePath {
			override.SourceEvidence = AppendUniqueStrings(current.SourceEvidence, override.SourceEvidence...)
			override.ProcessInstanceIDs = AppendUniqueStrings(current.ProcessInstanceIDs, override.ProcessInstanceIDs...)
			sort.Strings(override.SourceEvidence)
			sort.Strings(override.ProcessInstanceIDs)
		}
		merged.Overrides[id] = override
	}
	switch {
	case len(merged.Roots) > 0 && len(merged.Overrides) > 0:
		merged.Mode = "mixed"
	case len(merged.Roots) > 0:
		merged.Mode = "global_passphrase"
	default:
		merged.Mode = "per_database"
	}
	return merged
}

func MergeResults(existing *protocolmodel.Response, next protocolmodel.Response) protocolmodel.Response {
	if existing == nil {
		return next
	}
	merged := next
	merged.DatabaseKeys = map[string]string{}
	for path, key := range existing.DatabaseKeys {
		merged.DatabaseKeys[path] = key
	}
	for path, key := range next.DatabaseKeys {
		merged.DatabaseKeys[path] = key
	}
	merged.DatabaseProfiles = map[string]string{}
	for path, profile := range existing.DatabaseProfiles {
		merged.DatabaseProfiles[path] = profile
	}
	for path, profile := range next.DatabaseProfiles {
		merged.DatabaseProfiles[path] = profile
	}
	merged.DatabaseCredential = MergeDatabaseCredentials(existing.DatabaseCredential, next.DatabaseCredential)
	if merged.ImageKeys == nil {
		merged.ImageKeys = existing.ImageKeys
	}
	return merged
}

func IsAction(action string) bool {
	return action == "trigger_database" || action == "restart_wechat" ||
		action == "relogin_wechat" || action == "switch_to_target_account"
}

func IsPartialFinalizeAction(action string) bool {
	return action == "trigger_database" || action == "restart_wechat" || action == "relogin_wechat"
}

func ActionRetryLimit(action string) int {
	switch action {
	case "trigger_database":
		return 2
	case "restart_wechat", "relogin_wechat", "switch_to_target_account":
		return 1
	default:
		return 0
	}
}

func TerminalEmptyCoverageStatuses(scopes []string) (string, string) {
	databaseCoverageStatus := "not_requested"
	mediaCoverageStatus := "not_requested"
	for _, scope := range scopes {
		if scope == "database" {
			databaseCoverageStatus = "none"
		}
		if scope == "media" {
			mediaCoverageStatus = "none"
		}
	}
	return databaseCoverageStatus, mediaCoverageStatus
}

func DatabaseTargetStatus(scopes []string, latest *protocolmodel.Response) string {
	requested := false
	for _, scope := range scopes {
		requested = requested || scope == "database"
	}
	if !requested {
		return "not_requested"
	}
	if latest != nil && latest.Diagnostics.DatabaseCount > 0 {
		return "present"
	}
	return "none"
}
