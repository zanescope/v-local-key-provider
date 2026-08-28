//go:build !qualification

package provider

import "testing"

func TestDefaultBuildDoesNotExposeQualificationOverride(t *testing.T) {
	previous := append([]windowsCompatibilityEntry(nil), windowsCompatibilityRegistry...)
	t.Cleanup(func() { windowsCompatibilityRegistry = previous })
	t.Setenv("V_LOCAL_KEY_PROVIDER_QUALIFICATION_CONSENT", "I_HAVE_EXPLICIT_AUTHORIZATION_FOR_WINDOWS_QUALIFICATION")
	t.Setenv("V_LOCAL_KEY_PROVIDER_QUALIFICATION_CONFIG", `C:\untrusted\qualification.json`)
	if err := applyQualificationBootstrap("development"); err != nil {
		t.Fatalf("普通构建不应解析 qualification override：%v", err)
	}
	if qualificationRegistryEnabled() || len(windowsCompatibilityRegistry) != len(previous) {
		t.Fatal("普通构建启用了 qualification registry")
	}
}
