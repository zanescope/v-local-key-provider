package crypto

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha512"
	"testing"
)

func TestPBKDF2SHA512Key32MatchesReference(t *testing.T) {
	actual := PBKDF2SHA512Key32([]byte("password"), []byte("salt"), 8193, nil)
	expected, err := pbkdf2.Key(sha512.New, "password", []byte("salt"), 8193, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("bounded PBKDF2 diverged from the reference implementation")
	}
}

func TestPBKDF2SHA512Key32Cancels(t *testing.T) {
	checks := 0
	actual := PBKDF2SHA512Key32([]byte("password"), []byte("salt"), 10000, func() bool {
		checks++
		return true
	})
	if actual != nil || checks != 1 {
		t.Fatalf("derivation did not stop at its first cancellation checkpoint: result=%x checks=%d", actual, checks)
	}
}

func TestDefaultProfileRegistryIsCopyAndSummarizes(t *testing.T) {
	profiles := DefaultProfiles()
	profiles[0].ID = "mutated"
	if DefaultProfiles()[0].ID != DefaultProfileID {
		t.Fatal("default profile registry leaked mutable package state")
	}
	summaries := ProfileSummaries(DefaultProfiles())
	if len(summaries) != 1 || summaries[0].ID != DefaultProfileID || summaries[0].KDFIterations != 256_000 {
		t.Fatalf("unexpected default profile summary: %+v", summaries)
	}
}
