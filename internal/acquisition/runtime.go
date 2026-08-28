package acquisition

import (
	"runtime"
	"sync/atomic"

	credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

const defaultProfileID = providercrypto.DefaultProfileID

// Runtime 注入 compatibility registry 和归进程持有的敏感内存 hook。非 nil 的空 Profiles
// slice 会被保留，作为主动 fail-closed 的 registry。
type Runtime struct {
	Profiles       []providercrypto.Profile
	MarkSensitive  func([]byte)
	ClearSensitive func([]byte)
	CloneSensitive func([]byte) []byte
	NewOpaqueID    func() (string, error)
}

func DefaultRuntime() Runtime {
	return Runtime{
		Profiles:    providercrypto.DefaultProfiles(),
		NewOpaqueID: credentialmodel.RandomOpaqueID,
	}
}

func (value Runtime) normalized() Runtime {
	if value.Profiles == nil {
		value.Profiles = providercrypto.DefaultProfiles()
	} else {
		profiles := make([]providercrypto.Profile, len(value.Profiles))
		copy(profiles, value.Profiles)
		value.Profiles = profiles
	}
	if value.ClearSensitive == nil {
		value.ClearSensitive = clearBytes
	}
	if value.CloneSensitive == nil {
		value.CloneSensitive = func(source []byte) []byte {
			result := append([]byte(nil), source...)
			if value.MarkSensitive != nil {
				value.MarkSensitive(result)
			}
			return result
		}
	}
	if value.NewOpaqueID == nil {
		value.NewOpaqueID = credentialmodel.RandomOpaqueID
	}
	return value
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func (value Runtime) cryptoRuntime(cancelled *atomic.Bool, remaining ...workbudget.Budget) providercrypto.Runtime {
	return providercrypto.Runtime{
		Cancelled: func() bool {
			return cancelled != nil && cancelled.Load() || len(remaining) > 0 && remaining[0].Expired()
		},
		MarkSensitive:  value.MarkSensitive,
		ClearSensitive: value.ClearSensitive,
	}
}

func (collector *Collector) verifyRawDatabaseKey(rawKey, page []byte, cancelled *atomic.Bool, remaining ...workbudget.Budget) (providercrypto.KeyVerification, bool) {
	return providercrypto.VerifyRawDatabaseKey(collector.runtime.Profiles, rawKey, page, collector.runtime.cryptoRuntime(cancelled, remaining...))
}

func (collector *Collector) verifyDatabasePassphrase(passphrase, page []byte, cancelled *atomic.Bool, remaining ...workbudget.Budget) (providercrypto.KeyVerification, bool) {
	return collector.runtime.verifyDatabasePassphrase(passphrase, page, cancelled, remaining...)
}

func (value Runtime) verifyDatabasePassphrase(passphrase, page []byte, cancelled *atomic.Bool, remaining ...workbudget.Budget) (providercrypto.KeyVerification, bool) {
	return providercrypto.VerifyDatabasePassphrase(value.Profiles, passphrase, page, value.cryptoRuntime(cancelled, remaining...))
}

func validateRawDatabaseKey(key, page []byte) bool {
	runtime := DefaultRuntime().normalized()
	_, valid := providercrypto.VerifyRawDatabaseKey(runtime.Profiles, key, page, runtime.cryptoRuntime(nil))
	return valid
}

func validateV4DatabasePassphrase(passphrase, page []byte, cancelled *atomic.Bool, remaining ...budget) bool {
	runtime := DefaultRuntime().normalized()
	_, valid := providercrypto.VerifyDatabasePassphrase(runtime.Profiles, passphrase, page, runtime.cryptoRuntime(cancelled, remaining...))
	return valid
}
