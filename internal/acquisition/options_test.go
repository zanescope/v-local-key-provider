package acquisition

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

func optionPathPolicy() OptionPolicy {
	return OptionPolicy{
		IsLinkOrReparse: func(_ string, mode fs.FileMode) (bool, error) {
			return mode&fs.ModeSymlink != 0, nil
		},
	}
}

func optionRequestFixture(t *testing.T) protocolmodel.AcquireRequest {
	t.Helper()
	account := filepath.Join(t.TempDir(), "account")
	database := filepath.Join(account, "db_storage")
	if err := os.MkdirAll(database, 0o700); err != nil {
		t.Fatal(err)
	}
	return protocolmodel.AcquireRequest{
		AccountDir: account, DBDir: database,
		Scopes: []string{"database", "media"}, DeadlineMS: 75_000,
	}
}

func TestParseOptionsOwnsValidatedPathsScopesBudgetAndCatalogKey(t *testing.T) {
	request := optionRequestFixture(t)
	request.CatalogKey = strings.Repeat("ab", 32)
	policy := optionPathPolicy()
	policy.Now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	options, err := ParseOptions(request, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !options.Database || !options.Media || options.AccountDir == "" || options.DBDir == "" {
		t.Fatalf("validated options lost path or scope state: %+v", options)
	}
	if !bytes.Equal(options.CatalogKey, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("request catalog key was not preserved")
	}
	if options.Budget.IsUnlimited() || !options.Budget.Expired() {
		t.Fatal("request deadline was not transferred into the work budget")
	}
	platform := options.PlatformRequest()
	if platform.AccountDir != options.AccountDir || platform.DBDir != options.DBDir || !platform.Database || !platform.Media {
		t.Fatalf("platform request lost validated options: %+v", platform)
	}
}

func TestParseOptionsRejectsUnsafeOrInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*protocolmodel.AcquireRequest, *OptionPolicy)
		match  string
	}{
		{
			name: "duplicate scope",
			mutate: func(request *protocolmodel.AcquireRequest, _ *OptionPolicy) {
				request.Scopes = []string{"media", "media"}
			},
			match: "不能重复",
		},
		{
			name: "unknown scope",
			mutate: func(request *protocolmodel.AcquireRequest, _ *OptionPolicy) {
				request.Scopes = []string{"messages"}
			},
			match: "不支持",
		},
		{
			name: "malformed catalog key",
			mutate: func(request *protocolmodel.AcquireRequest, _ *OptionPolicy) {
				request.CatalogKey = "short"
			},
			match: "catalog_key 无效",
		},
		{
			name: "database outside account",
			mutate: func(request *protocolmodel.AcquireRequest, _ *OptionPolicy) {
				request.DBDir = t.TempDir()
			},
			match: "必须位于目标账号目录内",
		},
		{
			name: "reparse point",
			mutate: func(_ *protocolmodel.AcquireRequest, policy *OptionPolicy) {
				policy.IsLinkOrReparse = func(string, fs.FileMode) (bool, error) { return true, nil }
			},
			match: "不能是链接或 reparse point",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := optionRequestFixture(t)
			policy := optionPathPolicy()
			test.mutate(&request, &policy)
			if _, err := ParseOptions(request, policy); err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("invalid input error = %v, want match %q", err, test.match)
			}
		})
	}
}

func TestParseOptionsGeneratesCatalogKey(t *testing.T) {
	request := optionRequestFixture(t)
	want := bytes.Repeat([]byte{0x5a}, 32)
	policy := optionPathPolicy()
	policy.RandomCatalogKey = func() ([]byte, error) { return append([]byte(nil), want...), nil }
	options, err := ParseOptions(request, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(options.CatalogKey, want) {
		t.Fatalf("generated catalog key changed: %x", options.CatalogKey)
	}
}

func TestParseSecurityPostureOptionsNeverTouchesAcquisitionPaths(t *testing.T) {
	root := t.TempDir()
	request := protocolmodel.AcquireRequest{
		AccountDir: filepath.Join(root, "removed-account"),
		DBDir:      filepath.Join(root, "removed-account", "removed-database"),
		Scopes:     []string{"database"}, DeadlineMS: 1_000,
	}
	options, err := ParseSecurityPostureOptions(request, OptionPolicy{
		IsLinkOrReparse: func(string, fs.FileMode) (bool, error) {
			t.Fatal("posture-only parsing touched an acquisition path")
			return false, nil
		},
		RandomCatalogKey: func() ([]byte, error) {
			t.Fatal("posture-only parsing generated a catalog key")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.Database || options.Media || len(options.CatalogKey) != 0 {
		t.Fatalf("unexpected posture-only options: %+v", options)
	}
}
