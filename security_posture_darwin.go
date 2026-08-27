//go:build darwin

package provider

// defaultSecurityPostureStatus 以 csrutil 机器证据为依据。未知输出保持 not_evaluated，
// 绝不能提升为已验证状态。
func defaultSecurityPostureStatus() string {
	enabled, known := darwinSIPEnabled()
	if !known {
		return "not_evaluated"
	}
	if enabled {
		return "sip_enabled_verified"
	}
	return "sip_disabled_verified"
}
