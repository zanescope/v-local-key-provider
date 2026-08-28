package darwin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
)

func hookEncryptedDatabasePage(t *testing.T, keyHex, saltHex string) acquisitionmodel.DatabasePage {
	t.Helper()
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	const reserve = 80
	page := make([]byte, 4096)
	copy(page[:16], salt)
	plain := make([]byte, 4096-16-reserve)
	plain[0], plain[1] = 0x10, 0x00
	plain[4], plain[5], plain[6], plain[7] = reserve, 64, 32, 32
	iv := bytes.Repeat([]byte{0x5a}, aes.BlockSize)
	copy(page[4096-reserve:4096-reserve+aes.BlockSize], iv)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(page[16:4096-reserve], plain)
	profile, ok := providercrypto.RegisteredProfile(providercrypto.DefaultProfiles(), providercrypto.DefaultProfileID)
	if !ok {
		t.Fatal("default profile is not registered")
	}
	macKey := providercrypto.ProfileHMACKey(profile, key, salt, providercrypto.Runtime{})
	defer func() {
		for index := range macKey {
			macKey[index] = 0
		}
	}()
	mac := hmac.New(sha512.New, macKey)
	_, _ = mac.Write(page[16 : 4096-profile.HMACSize])
	_, _ = mac.Write([]byte{1, 0, 0, 0})
	copy(page[4096-profile.HMACSize:], mac.Sum(nil))
	return acquisitionmodel.DatabasePage{Salt: saltHex, Data: page, ProfileID: providercrypto.DefaultProfileID}
}

func TestRoundsTwoPBKDFCaptureMapsRawKeyUsingXORSalt(t *testing.T) {
	keyHex := strings.Repeat("37", 32)
	saltHex := strings.Repeat("a4", 16)
	page := hookEncryptedDatabasePage(t, keyHex, saltHex)
	page.Path = "message.db"
	targets := acquisitionmodel.Targets{
		BySalt: map[string][]string{saltHex: {page.Path}}, Pages: []acquisitionmodel.DatabasePage{page}, Count: 1,
	}
	collector := acquisitionmodel.NewCollector(targets, acquisitionmodel.MediaEvidence{}, acquisitionmodel.DefaultRuntime())
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatal(err)
	}
	for index := range salt {
		salt[index] ^= 0x3a
	}
	output := "VLOCALPBKDF=2,5,2,32,32," + keyHex + "," + hex.EncodeToString(salt) + "\n"
	driver := NewHookDriver(HookRuntime{})
	if captures := driver.consumeCaptures(output, collector); captures != 1 {
		t.Fatalf("capture count = %d, want 1", captures)
	}
	keys, ambiguous := collector.DatabaseKeys(targets)
	if ambiguous != 0 || keys[page.Path] != keyHex {
		t.Fatalf("rounds=2 PBKDF evidence did not map to the raw key: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestUnrelatedPBKDFCaptureIsNotCountedAsUsed(t *testing.T) {
	targets := acquisitionmodel.Targets{Pages: []acquisitionmodel.DatabasePage{{Salt: strings.Repeat("ab", 16)}}}
	collector := acquisitionmodel.NewCollector(targets, acquisitionmodel.MediaEvidence{}, acquisitionmodel.DefaultRuntime())
	driver := NewHookDriver(HookRuntime{})
	if captures := driver.consumeCaptures("VLOCALPBKDF=2,3,1,4,16,01020304,aabbccdd\n", collector); captures != 0 {
		t.Fatalf("unvalidated PBKDF event counted as accepted: %d", captures)
	}
}

func TestCapturedSecretRequiresAPIDBoundIdentityMarker(t *testing.T) {
	driver := NewHookDriver(HookRuntime{Native: &fixtureNativeDriver{processes: []Process{{PID: 42}}}})
	output := "VLOCALKEY32=" + strings.Repeat("ab", 32) + "\n"
	if driver.captureIdentityMatches(output, fixtureEvidence(), 42) {
		t.Fatal("capture without a PID marker passed target identity revalidation")
	}
	if !driver.captureIdentityMatches("VLOCALHOOKS=1\n", fixtureEvidence(), 42) {
		t.Fatal("status-only output was incorrectly treated as secret capture evidence")
	}
}

func TestHookOutputBufferBoundsAndClearsCapturedOutput(t *testing.T) {
	driver := NewHookDriver(HookRuntime{})
	buffer := &hookOutputBuffer{driver: driver, limit: 4}
	if written, err := buffer.Write([]byte("abcdef")); err != nil || written != 6 {
		t.Fatalf("hook output write = %d, %v", written, err)
	}
	snapshot := buffer.snapshot()
	if string(snapshot) != "abcd" {
		t.Fatalf("bounded hook output = %q", snapshot)
	}
	buffer.zero()
	if len(buffer.data) != 0 {
		t.Fatal("hook output retained data after zero")
	}
	driver.clear(snapshot)
	if !bytes.Equal(snapshot, make([]byte, len(snapshot))) {
		t.Fatalf("hook output snapshot was not cleared: %v", snapshot)
	}
}

func TestMergeHookSnapshotsRetainsRouteHistoryAndUsedState(t *testing.T) {
	merged := mergeHookSnapshots(
		platformmodel.HookSnapshot{TargetFound: 1, Installed: true, TriggerNeeded: true, Route: "direct"},
		platformmodel.HookSnapshot{Captures: 1, Used: true, Route: "wait", RouteHistory: "wait"},
	)
	if !merged.Used || merged.TriggerNeeded || merged.Captures != 1 || merged.TargetFound != 1 ||
		merged.Route != "direct" || merged.RouteHistory != "direct\x00wait" {
		t.Fatalf("unexpected merged hook status: %#v", merged)
	}
}

func TestHookWatchdogRejectsMalformedArgumentsBeforeOpeningLivenessFD(t *testing.T) {
	driver := NewHookDriver(HookRuntime{})
	for _, arguments := range [][]string{nil, {"-b", "-s", ""}, {"-b", "-p", "zero", "-s", "/tmp/hook"}} {
		if err := driver.RunWatchdog(arguments); err == nil {
			t.Fatalf("malformed watchdog arguments were accepted: %v", arguments)
		}
	}
}
