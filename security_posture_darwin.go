//go:build darwin

package provider

// defaultSecurityPostureStatus is based on csrutil machine evidence. Unknown
// output stays not_evaluated; it must never be promoted to a verified posture.
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
