package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
)

const DefaultProfileID = "wcdb-v4-sha512-256000-r80"

// Profile describes every parameter needed to derive and authenticate a
// WCDB/SQLCipher first page. A plausible decrypted SQLite header is never
// sufficient without the page HMAC.
type Profile struct {
	ID                  string
	CipherAlgorithm     string
	KeySize             int
	PageSize            int
	PlaintextHeaderSize int
	ReserveSize         int
	KDFAlgorithm        string
	KDFPRF              string
	KDFIterations       int
	HMACAlgorithm       string
	HMACKDFAlgorithm    string
	HMACKDFIterations   int
	HMACSaltXORMask     byte
	HMACSize            int
	PageNumberEndian    string
	HMACInputLayout     string
}

type Summary struct {
	ID                  string `json:"profile_id"`
	CipherAlgorithm     string `json:"cipher_algorithm"`
	KeySize             int    `json:"key_size"`
	PageSize            int    `json:"page_size"`
	PlaintextHeaderSize int    `json:"plaintext_header_size"`
	ReserveSize         int    `json:"reserve_size"`
	KDFAlgorithm        string `json:"kdf_algorithm"`
	KDFPRF              string `json:"kdf_prf"`
	KDFIterations       int    `json:"kdf_iterations"`
	HMACAlgorithm       string `json:"hmac_algorithm"`
	HMACKDFAlgorithm    string `json:"hmac_kdf_algorithm"`
	HMACKDFIterations   int    `json:"hmac_kdf_iterations"`
	HMACInputLayout     string `json:"hmac_input_layout"`
	PageNumberEndian    string `json:"page_number_endian"`
}

type KeyVerification struct {
	ProfileID string
	KeyHex    string
}

// Runtime keeps cancellation and sensitive-memory ownership at the caller's
// process boundary. ClearSensitive must erase the supplied slice.
type Runtime struct {
	Cancelled      func() bool
	MarkSensitive  func([]byte)
	ClearSensitive func([]byte)
}

func (runtime Runtime) mark(value []byte) {
	if len(value) > 0 && runtime.MarkSensitive != nil {
		runtime.MarkSensitive(value)
	}
}

func (runtime Runtime) clear(value []byte) {
	if len(value) == 0 {
		return
	}
	if runtime.ClearSensitive != nil {
		runtime.ClearSensitive(value)
		return
	}
	zero(value)
}

var defaultProfiles = []Profile{
	{
		ID:                  DefaultProfileID,
		CipherAlgorithm:     "aes-256-cbc",
		KeySize:             32,
		PageSize:            4096,
		PlaintextHeaderSize: 16,
		ReserveSize:         80,
		KDFAlgorithm:        "pbkdf2",
		KDFPRF:              "hmac-sha512",
		KDFIterations:       256_000,
		HMACAlgorithm:       "hmac-sha512",
		HMACKDFAlgorithm:    "pbkdf2",
		HMACKDFIterations:   2,
		HMACSaltXORMask:     0x3a,
		HMACSize:            sha512.Size,
		PageNumberEndian:    "little-endian",
		HMACInputLayout:     "page_without_salt_and_hmac_then_page_number",
	},
}

func DefaultProfiles() []Profile {
	return append([]Profile(nil), defaultProfiles...)
}

func RegisteredProfile(profiles []Profile, id string) (Profile, bool) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

func ProfileSummaries(profiles []Profile) []Summary {
	result := make([]Summary, 0, len(profiles))
	for _, profile := range profiles {
		result = append(result, Summary{
			ID: profile.ID, CipherAlgorithm: profile.CipherAlgorithm,
			KeySize: profile.KeySize, PageSize: profile.PageSize,
			PlaintextHeaderSize: profile.PlaintextHeaderSize, ReserveSize: profile.ReserveSize,
			KDFAlgorithm: profile.KDFAlgorithm, KDFPRF: profile.KDFPRF,
			KDFIterations: profile.KDFIterations, HMACAlgorithm: profile.HMACAlgorithm,
			HMACKDFAlgorithm: profile.HMACKDFAlgorithm, HMACKDFIterations: profile.HMACKDFIterations,
			HMACInputLayout: profile.HMACInputLayout, PageNumberEndian: profile.PageNumberEndian,
		})
	}
	return result
}

func DeriveProfileKey(profile Profile, passphrase, salt []byte, runtime Runtime) []byte {
	if profile.KDFAlgorithm != "pbkdf2" || profile.KDFPRF != "hmac-sha512" || len(salt) != profile.PlaintextHeaderSize {
		return nil
	}
	result := PBKDF2SHA512Key32(passphrase, salt, profile.KDFIterations, runtime.Cancelled)
	runtime.mark(result)
	return result
}

func ProfileHMACKey(profile Profile, rawKey, fileSalt []byte, runtime Runtime) []byte {
	if profile.HMACAlgorithm != "hmac-sha512" || profile.HMACKDFAlgorithm != "pbkdf2" ||
		len(rawKey) != profile.KeySize || len(fileSalt) != profile.PlaintextHeaderSize {
		return nil
	}
	macSalt := make([]byte, len(fileSalt))
	defer runtime.clear(macSalt)
	for index := range fileSalt {
		macSalt[index] = fileSalt[index] ^ profile.HMACSaltXORMask
	}
	result := PBKDF2SHA512Key32(rawKey, macSalt, profile.HMACKDFIterations, runtime.Cancelled)
	runtime.mark(result)
	return result
}

func VerifyRawKeyWithProfile(profile Profile, rawKey, page []byte, runtime Runtime) bool {
	if profile.CipherAlgorithm != "aes-256-cbc" || profile.HMACInputLayout != "page_without_salt_and_hmac_then_page_number" ||
		len(rawKey) != profile.KeySize || len(page) < profile.PageSize || profile.ReserveSize < aes.BlockSize+profile.HMACSize {
		return false
	}
	page = page[:profile.PageSize]
	ivStart := profile.PageSize - profile.ReserveSize
	macStart := profile.PageSize - profile.HMACSize
	if ivStart < profile.PlaintextHeaderSize || ivStart+aes.BlockSize > macStart {
		return false
	}
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return false
	}
	iv := page[ivStart : ivStart+aes.BlockSize]
	for _, offset := range []int{profile.PlaintextHeaderSize, 0} {
		needed := aes.BlockSize
		if offset == 0 {
			needed = 2 * aes.BlockSize
		}
		if offset+needed > ivStart {
			continue
		}
		decrypted := make([]byte, 0, needed)
		defer runtime.clear(decrypted)
		previous := iv
		for start := offset; start < offset+needed; start += aes.BlockSize {
			raw := make([]byte, aes.BlockSize)
			block.Decrypt(raw, page[start:start+aes.BlockSize])
			decrypted = append(decrypted, xorBlock(raw, previous)...)
			runtime.clear(raw)
			previous = page[start : start+aes.BlockSize]
		}
		if !validSQLitePageHeaderForPageSize(decrypted, profile.PageSize, profile.ReserveSize, offset) {
			continue
		}
		macKey := ProfileHMACKey(profile, rawKey, page[:profile.PlaintextHeaderSize], runtime)
		defer runtime.clear(macKey)
		if len(macKey) != 32 {
			return false
		}
		mac := hmac.New(sha512.New, macKey)
		_, _ = mac.Write(page[profile.PlaintextHeaderSize:macStart])
		var pageNumber [4]byte
		switch profile.PageNumberEndian {
		case "little-endian":
			binary.LittleEndian.PutUint32(pageNumber[:], 1)
		case "big-endian":
			binary.BigEndian.PutUint32(pageNumber[:], 1)
		default:
			return false
		}
		_, _ = mac.Write(pageNumber[:])
		actualMAC := mac.Sum(nil)
		defer runtime.clear(actualMAC)
		return hmac.Equal(actualMAC, page[macStart:profile.PageSize])
	}
	return false
}

func VerifyRawDatabaseKey(profiles []Profile, rawKey, page []byte, runtime Runtime) (KeyVerification, bool) {
	for _, profile := range profiles {
		if VerifyRawKeyWithProfile(profile, rawKey, page, runtime) {
			return KeyVerification{ProfileID: profile.ID, KeyHex: hex.EncodeToString(rawKey)}, true
		}
	}
	return KeyVerification{}, false
}

func VerifyDatabasePassphrase(profiles []Profile, passphrase, page []byte, runtime Runtime) (KeyVerification, bool) {
	for _, profile := range profiles {
		if len(page) < profile.PlaintextHeaderSize {
			continue
		}
		rawKey := DeriveProfileKey(profile, passphrase, page[:profile.PlaintextHeaderSize], runtime)
		defer runtime.clear(rawKey)
		if len(rawKey) != 32 {
			continue
		}
		if VerifyRawKeyWithProfile(profile, rawKey, page, runtime) {
			return KeyVerification{ProfileID: profile.ID, KeyHex: hex.EncodeToString(rawKey)}, true
		}
	}
	return KeyVerification{}, false
}

func xorBlock(block, previous []byte) []byte {
	plain := make([]byte, aes.BlockSize)
	for index := range plain {
		plain[index] = block[index] ^ previous[index]
	}
	return plain
}

func validSQLitePageHeaderForPageSize(plain []byte, expectedPageSize, reserve, offset int) bool {
	if offset == 0 {
		if len(plain) < 24 || string(plain[:16]) != "SQLite format 3\x00" {
			return false
		}
		plain = plain[16:]
	}
	if len(plain) < 8 {
		return false
	}
	pageSize := int(plain[0])<<8 | int(plain[1])
	if pageSize == 1 {
		pageSize = 65536
	}
	validPageSize := pageSize >= 512 && pageSize <= 65536 && pageSize&(pageSize-1) == 0
	if expectedPageSize > 0 && pageSize != expectedPageSize {
		return false
	}
	return validPageSize && int(plain[4]) == reserve && plain[5] == 64 && plain[6] == 32 && plain[7] == 32
}

func validSQLitePageHeader(plain []byte, reserve, offset int) bool {
	return validSQLitePageHeaderForPageSize(plain, 0, reserve, offset)
}
