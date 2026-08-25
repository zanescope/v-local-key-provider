package provider

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestRawKeyRequiresFirstPageHMAC(t *testing.T) {
	keyHex := strings.Repeat("12", 32)
	saltHex := strings.Repeat("ab", 16)
	page := encryptedDatabasePage(t, keyHex, saltHex)
	key, _ := hex.DecodeString(keyHex)
	verification, valid := verifyRawDatabaseKey(key, page.Data, nil)
	if !valid || verification.KeyHex != keyHex || verification.ProfileID != defaultProfileID {
		t.Fatalf("valid raw key was rejected: verification=%+v valid=%v", verification, valid)
	}

	tampered := append([]byte(nil), page.Data...)
	tampered[len(tampered)-1] ^= 0xff
	if _, valid := verifyRawDatabaseKey(key, tampered, nil); valid {
		t.Fatal("a plausible decrypted header without a valid first-page HMAC was accepted")
	}
}

func TestProfileRegistryCanSelectANonDefaultRegisteredProfile(t *testing.T) {
	keyHex := strings.Repeat("34", 32)
	page := encryptedDatabasePage(t, keyHex, strings.Repeat("cd", 16))
	previous := profileRegistry
	second := previous[0]
	second.ID = "fixture-wcdb-migration-profile"
	profileRegistry = []cipherProfile{second}
	t.Cleanup(func() { profileRegistry = previous })

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	verification, valid := verifyRawDatabaseKey(key, page.Data, nil)
	if !valid || verification.ProfileID != second.ID {
		t.Fatalf("non-default registered profile was unreachable: valid=%v verification=%+v", valid, verification)
	}
}

func TestPassphraseReturnsDatabaseSpecificEffectiveKey(t *testing.T) {
	passphraseHex := strings.Repeat("7b", 32)
	saltHex := strings.Repeat("2c", 16)
	page := encryptedV4PassphrasePage(t, passphraseHex, saltHex)
	passphrase, _ := hex.DecodeString(passphraseHex)
	verification, valid := verifyDatabasePassphrase(passphrase, page.Data, nil)
	if !valid || verification.ProfileID != defaultProfileID || verification.KeyHex == passphraseHex {
		t.Fatalf("passphrase did not produce an effective per-database key: %+v valid=%v", verification, valid)
	}
	if len(verification.KeyHex) != 64 {
		t.Fatalf("effective key has invalid length: %d", len(verification.KeyHex))
	}
}
