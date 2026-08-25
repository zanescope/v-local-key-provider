//go:build windows

package windows

import "testing"

func TestObservedPathsBindTargetAndOtherAccounts(t *testing.T) {
	target := `C:\Users\tester\Documents\xwechat_files\account-a`
	database := target + `\db_storage`
	if got := ClassifyObservedPaths([]string{database + `\message\message_0.db`}, target, database); got != "target" {
		t.Fatalf("target database handle binding=%q", got)
	}
	other := `C:\Users\tester\Documents\xwechat_files\account-b\db_storage\message\message_0.db`
	if got := ClassifyObservedPaths([]string{other}, target, database); got != "other" {
		t.Fatalf("other-account database handle binding=%q", got)
	}
	if got := ClassifyObservedPaths([]string{database + `\message\message_0.db`, other}, target, database); got != "unknown" {
		t.Fatalf("mixed target/other handles must not claim a live target binding: %q", got)
	}
	if got := ClassifyObservedPaths([]string{`C:\Windows\System32\kernel32.dll`}, target, database); got != "unknown" {
		t.Fatalf("unrelated handle binding=%q", got)
	}
	for _, nonDatabase := range []string{
		target + `\logs\session.log`,
		target + `\config\settings.db`,
		`C:\Users\tester\Documents\xwechat_files\account-b\db_storage\logs\trace.log`,
	} {
		if got := ClassifyObservedPaths([]string{nonDatabase}, target, database); got != "unknown" {
			t.Fatalf("non-target-database handle %q promoted account binding to %q", nonDatabase, got)
		}
	}
}

func TestObservedPathNormalizationHandlesDevicePrefixAndCase(t *testing.T) {
	target := `c:\users\tester\documents\xwechat_files\account-a`
	database := target + `\db_storage`
	observed := `\\?\C:\Users\Tester\Documents\xwechat_files\ACCOUNT-A\db_storage\contact\contact.db`
	if got := ClassifyObservedPaths([]string{observed}, target, database); got != "target" {
		t.Fatalf("device-prefixed target binding=%q", got)
	}
}
