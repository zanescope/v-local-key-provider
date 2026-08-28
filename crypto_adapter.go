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

// pbkdf2SHA512 有意保留并行 passphrase 验证所需的有界取消 hook。其输出会登记为敏感
// 数据，直到持有它的调用方完成清理。
func pbkdf2SHA512(password, salt []byte, iterations int, cancelled *atomic.Bool, remaining ...budget) []byte {
	result := providercrypto.PBKDF2SHA512Key32(password, salt, iterations, profileCryptoRuntime(cancelled, remaining).Cancelled)
	markSensitiveBytes(result)
	return result
}

func profileHMACKey(profile cipherProfile, rawKey, fileSalt []byte, cancelled *atomic.Bool, remaining ...budget) []byte {
	return providercrypto.ProfileHMACKey(profile, rawKey, fileSalt, profileCryptoRuntime(cancelled, remaining))
}

func verifyRawDatabaseKey(rawKey, page []byte, cancelled *atomic.Bool, remaining ...budget) (keyVerification, bool) {
	return providercrypto.VerifyRawDatabaseKey(profileRegistry, rawKey, page, profileCryptoRuntime(cancelled, remaining))
}

func verifyDatabasePassphrase(passphrase, page []byte, cancelled *atomic.Bool, remaining ...budget) (keyVerification, bool) {
	return providercrypto.VerifyDatabasePassphrase(profileRegistry, passphrase, page, profileCryptoRuntime(cancelled, remaining))
}
