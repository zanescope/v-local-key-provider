package provider

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

func encryptedDatabasePage(t *testing.T, keyHex, saltHex string) databasePage {
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
	profile, ok := registeredProfile(defaultProfileID)
	if !ok {
		t.Fatal("default profile is not registered")
	}
	macKey := profileHMACKey(profile, key, salt, nil)
	defer zeroBytes(macKey)
	mac := hmac.New(sha512.New, macKey)
	_, _ = mac.Write(page[16 : 4096-profile.HMACSize])
	_, _ = mac.Write([]byte{1, 0, 0, 0})
	copy(page[4096-profile.HMACSize:], mac.Sum(nil))
	return databasePage{Salt: saltHex, Data: page}
}

func encryptedDatabasePageAt(t *testing.T, keyHex, saltHex, path string) databasePage {
	t.Helper()
	page := encryptedDatabasePage(t, keyHex, saltHex)
	page.Path = path
	return page
}

func encryptedV4PassphrasePage(t *testing.T, passphraseHex, saltHex string) databasePage {
	t.Helper()
	passphrase, err := hex.DecodeString(passphraseHex)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatal(err)
	}
	encKey := pbkdf2SHA512(passphrase, salt, v4KDFIterations, nil)
	defer zeroBytes(encKey)
	page := encryptedDatabasePage(t, hex.EncodeToString(encKey), saltHex)
	macSalt := make([]byte, len(salt))
	for index := range salt {
		macSalt[index] = salt[index] ^ 0x3a
	}
	macKey := pbkdf2SHA512(encKey, macSalt, 2, nil)
	defer zeroBytes(macKey)
	mac := hmac.New(sha512.New, macKey)
	_, _ = mac.Write(page.Data[16:4032])
	_, _ = mac.Write([]byte{1, 0, 0, 0})
	copy(page.Data[4032:4096], mac.Sum(nil))
	page.Path = "message/message_0.db"
	return page
}
