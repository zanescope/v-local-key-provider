package provider

import diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"

type diagnostics = diagnosticmodel.Diagnostics

func platformDiagnosticDefaults() diagnosticmodel.PlatformDefaults {
	return diagnosticmodel.PlatformDefaults{
		SecurityPostureStatus: defaultSecurityPostureStatus(),
		// 当前构建没有 Shadow 的 production 实现。该能力事实应保持显式注入，不从平台
		// 状态推断。
		DarwinShadowRouteStatus: "unavailable_in_build",
	}
}

func requestedScopes(database, media bool) []string {
	return diagnosticmodel.RequestedScopes(database, media)
}

func applyPlatformDiagnosticDefaults(diag *diagnostics) {
	diagnosticmodel.ApplyPlatformDefaults(diag, platformDiagnosticDefaults())
}

func newDiagnostics(platform string, scopes []string) diagnostics {
	return diagnosticmodel.NewWithPlatformDefaults(platform, scopes, platformDiagnosticDefaults())
}
