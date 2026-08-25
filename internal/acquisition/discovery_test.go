package acquisition

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
)

func discoverDatabaseTargets(dbDir string, remaining budget) (databaseTargets, error) {
	key, err := catalogmodel.RandomKey()
	if err != nil {
		return databaseTargets{}, err
	}
	defer clearBytes(key)
	return DiscoverDatabaseTargets(dbDir, remaining, key, catalogmodel.PlatformPolicy{
		FileIdentity: func(file *os.File) (string, error) {
			info, err := file.Stat()
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s:%d:%d", file.Name(), info.Size(), info.ModTime().UnixNano()), nil
		},
		IsLinkOrReparse: func(_ string, mode fs.FileMode) (bool, error) {
			return mode&os.ModeSymlink != 0, nil
		},
		CanonicalPathKey: func(path string) string {
			return strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
		},
		AcquisitionExpired: remaining.Expired,
	})
}

func TestDiscoverDatabaseTargetsUsesFirst16BytesAsSalt(t *testing.T) {
	root := t.TempDir()
	salt := bytes.Repeat([]byte{0xab}, 16)
	path := filepath.Join(root, "contact", "contact.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(salt, bytes.Repeat([]byte{0}, 4096-len(salt))...), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, err := discoverDatabaseTargets(root, unlimitedBudget())
	if err != nil {
		t.Fatal(err)
	}
	paths := targets.BySalt[hex.EncodeToString(salt)]
	if len(paths) != 1 || paths[0] != filepath.Join("contact", "contact.db") {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestMediaEvidenceFindsV2BlockAndV3XOR(t *testing.T) {
	account := t.TempDir()
	cache := filepath.Join(account, "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	v2 := append(append([]byte{}, v2Magic...), bytes.Repeat([]byte{0}, 9)...)
	v2 = append(v2, bytes.Repeat([]byte{0x42}, 16)...)
	v2 = append(v2, 0xaa, 0xbb)
	if err := os.WriteFile(filepath.Join(cache, "v2.dat"), v2, 0o600); err != nil {
		t.Fatal(err)
	}
	key := byte(0xf5)
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	encrypted := make([]byte, len(png))
	for index := range png {
		encrypted[index] = png[index] ^ key
	}
	if err := os.WriteFile(filepath.Join(cache, "v3.dat"), encrypted, 0o600); err != nil {
		t.Fatal(err)
	}

	evidence := discoverMediaEvidence(account, unlimitedBudget())
	if len(evidence.V2Blocks) != 1 || evidence.XORCandidates[key] != 1 {
		t.Fatalf("unexpected media evidence: %#v", evidence)
	}
}

func TestSelectDominantXORRejectsAmbiguityAndAcceptsConsensus(t *testing.T) {
	evidence := mediaEvidence{XORCandidates: map[byte]int{0x11: 100, 0x22: 10, 0x33: 1}}
	selected, ok, leading, second := selectDominantXOR(evidence)
	if !ok || leading != 100 || second != 10 || selected.XORCandidates[0x11] != 100 {
		t.Fatalf("主导候选选择异常：selected=%v ok=%v leading=%d second=%d", selected.XORCandidates, ok, leading, second)
	}
	ambiguous := mediaEvidence{XORCandidates: map[byte]int{0x11: 10, 0x22: 4}}
	if _, ok, _, _ := selectDominantXOR(ambiguous); ok {
		t.Fatal("接近的 XOR 候选不应被接受")
	}
}

func TestKVCommCandidateMustMatchV2AndXOREvidence(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	kvcomm := filepath.Join(appData, "Tencent", "xwechat", "net", "kvcomm")
	if err := os.MkdirAll(kvcomm, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(kvcomm, "key_245_test.statistic"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APPDATA", appData)
	account := filepath.Join(t.TempDir(), "wxid_example_1234")
	candidate := deriveImageKeys(245, filepath.Base(account))
	block, err := aes.NewCipher([]byte(candidate.AES))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte{0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var encrypted [16]byte
	block.Encrypt(encrypted[:], plain)
	evidence := mediaEvidence{
		V2Blocks:      [][16]byte{encrypted},
		XORCandidates: map[byte]int{byte(candidate.XOR): 20},
	}
	resolved, candidates, verified := resolveKVCommMedia(account, evidence)
	if candidates != 1 || verified != 1 || resolved == nil || *resolved != candidate {
		t.Fatalf("kvcomm 候选解析异常：resolved=%v candidates=%d verified=%d", resolved, candidates, verified)
	}
}

func TestAccountNameCandidatesHandlesWeChatSuffixes(t *testing.T) {
	got := accountNameCandidates("/Users/example/xwechat_files/dong_zzc_df91")
	want := []string{"dong_zzc_df91", "dong_zzc"}
	if len(got) != len(want) {
		t.Fatalf("unexpected account candidates: %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("candidate[%d]=%q, want %q; all=%#v", index, got[index], want[index], got)
		}
	}
}

func TestKVCommCandidateUsesValidatedAccountSuffix(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("APPDATA", appData)
	root := filepath.Join(appData, "Tencent", "xwechat", "net", "kvcomm")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "key_708278060_sample.statistic"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	account := filepath.Join(t.TempDir(), "dong_zzc_df91")
	want := deriveImageKeysExact(708278060, "dong_zzc")
	cipher, err := aes.NewCipher([]byte(want.AES))
	if err != nil {
		t.Fatal(err)
	}
	plain := [16]byte{0xff, 0xd8, 0xff, 0xe0}
	var encrypted [16]byte
	cipher.Encrypt(encrypted[:], plain[:])
	resolved, candidates, verified := resolveKVCommMedia(account, mediaEvidence{
		V2Blocks: [][16]byte{encrypted}, XORCandidates: map[byte]int{byte(want.XOR): 9},
	})
	if candidates != 1 || verified != 1 || resolved == nil || *resolved != want {
		t.Fatalf("suffix candidate was not verified: resolved=%v candidates=%d verified=%d", resolved, candidates, verified)
	}
}

func TestKVCommCandidateRejectsInsufficientEvidenceForAmbiguousAccountNames(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("APPDATA", appData)
	root := filepath.Join(appData, "Tencent", "xwechat", "net", "kvcomm")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "key_245_ambiguous.statistic"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	account := filepath.Join(t.TempDir(), "alice_abcd")
	resolved, candidates, verified := resolveKVCommMedia(account, mediaEvidence{
		V2Blocks: [][16]byte{{0x89, 'P', 'N', 'G'}}, XORCandidates: map[byte]int{byte(245): 9},
	})
	if resolved != nil || candidates != 1 || verified != 0 {
		t.Fatalf("ambiguous account names without matching AES evidence should be rejected: resolved=%v candidates=%d verified=%d", resolved, candidates, verified)
	}
}

func TestDiscoveryStopsWhenBudgetExpired(t *testing.T) {
	root := t.TempDir()
	account := filepath.Join(root, "account")
	if err := os.MkdirAll(filepath.Join(account, "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		path := filepath.Join(account, "cache", fmt.Sprintf("sample-%03d.dat", index))
		if err := os.WriteFile(path, []byte("not a media container"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expired := newBudget(time.Now().Add(-time.Second), 1)
	if evidence := discoverMediaEvidence(account, expired); len(evidence.V2Blocks) != 0 || len(evidence.XORCandidates) != 0 {
		t.Fatalf("expired discovery should not inspect media files: %#v", evidence)
	}

	dbDir := filepath.Join(root, "db")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		path := filepath.Join(dbDir, fmt.Sprintf("sample-%03d.db", index))
		if err := os.WriteFile(path, bytes.Repeat([]byte{0x42}, 4096), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	targets, err := discoverDatabaseTargets(dbDir, expired)
	if err != nil {
		t.Fatalf("expired database discovery returned error: %v", err)
	}
	if targets.Count != 0 {
		t.Fatalf("expired discovery should not inspect database files: %#v", targets)
	}
}

func TestMacOSKVCommRootsDeriveContainerAndAccountPaths(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	accountBase := filepath.Join(t.TempDir(), "container")
	account := filepath.Join(accountBase, "xwechat_files", "wxid_example")
	roots := macOSKVCommRoots(account, home)
	wantHome := filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "app_data", "net", "kvcomm")
	wantAccount := filepath.Join(accountBase, "app_data", "net", "kvcomm")
	seenHome, seenAccount := false, false
	for _, root := range roots {
		if root == wantHome {
			seenHome = true
		}
		if root == wantAccount {
			seenAccount = true
		}
	}
	if !seenHome || !seenAccount {
		t.Fatalf("macOS kvcomm roots missing expected paths: %v", roots)
	}
}

func TestMacOSKVCommRootsRemainAvailableWithWindowsAPPDATA(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin path discovery")
	}
	appData := filepath.Join(t.TempDir(), "appdata")
	t.Setenv("APPDATA", appData)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	roots := kvcommRoots(filepath.Join(t.TempDir(), "account"))
	want := filepath.Join(home, "Library", "Containers", "com.tencent.xinWeChat", "Data", "Documents", "app_data", "net", "kvcomm")
	for _, root := range roots {
		if root == want {
			return
		}
	}
	t.Fatalf("Darwin kvcomm roots were suppressed by APPDATA: %v", roots)
}
