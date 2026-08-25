package provider

import (
	"sync/atomic"

	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
)

const defaultProfileID = providercrypto.DefaultProfileID

type cipherProfile = providercrypto.Profile
type profileSummary = providercrypto.Summary
type keyVerification = providercrypto.KeyVerification

var profileRegistry = providercrypto.DefaultProfiles()

func registeredProfile(id string) (cipherProfile, bool) {
	return providercrypto.RegisteredProfile(profileRegistry, id)
}

func profileSummaries() []profileSummary {
	return providercrypto.ProfileSummaries(profileRegistry)
}

func profileCryptoRuntime(cancelled *atomic.Bool, remaining []budget) providercrypto.Runtime {
	return providercrypto.Runtime{
		Cancelled: func() bool {
			return (cancelled != nil && cancelled.Load()) || (len(remaining) > 0 && remaining[0].expired())
		},
		MarkSensitive:  markSensitiveBytes,
		ClearSensitive: zeroBytes,
	}
}

// pbkdf2SHA512 intentionally keeps the bounded cancellation hook required by
// parallel passphrase validation. Its output is registered as sensitive until
// the owning caller clears it.
func pbkdf2SHA512(password, salt []byte, iterations int, cancelled *atomic.Bool, remaining ...budget) []byte {
	result := providercrypto.PBKDF2SHA512Key32(password, salt, iterations, profileCryptoRuntime(cancelled, remaining).Cancelled)
	markSensitiveBytes(result)
	return result
}

func deriveProfileKey(profile cipherProfile, passphrase, salt []byte, cancelled *atomic.Bool, remaining ...budget) []byte {
	return providercrypto.DeriveProfileKey(profile, passphrase, salt, profileCryptoRuntime(cancelled, remaining))
}

func profileHMACKey(profile cipherProfile, rawKey, fileSalt []byte, cancelled *atomic.Bool, remaining ...budget) []byte {
	return providercrypto.ProfileHMACKey(profile, rawKey, fileSalt, profileCryptoRuntime(cancelled, remaining))
}

func verifyRawKeyWithProfile(profile cipherProfile, rawKey, page []byte, cancelled *atomic.Bool, remaining ...budget) bool {
	return providercrypto.VerifyRawKeyWithProfile(profile, rawKey, page, profileCryptoRuntime(cancelled, remaining))
}

func verifyRawDatabaseKey(rawKey, page []byte, cancelled *atomic.Bool, remaining ...budget) (keyVerification, bool) {
	return providercrypto.VerifyRawDatabaseKey(profileRegistry, rawKey, page, profileCryptoRuntime(cancelled, remaining))
}

func verifyDatabasePassphrase(passphrase, page []byte, cancelled *atomic.Bool, remaining ...budget) (keyVerification, bool) {
	return providercrypto.VerifyDatabasePassphrase(profileRegistry, passphrase, page, profileCryptoRuntime(cancelled, remaining))
}
