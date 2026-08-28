//go:build !darwin

package provider

func defaultSecurityPostureStatus() string {
	return "not_applicable"
}
