package provider

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
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
	mac := hmac.New(sha512.New, macKey)
	_, _ = mac.Write(page[16 : 4096-profile.HMACSize])
	_, _ = mac.Write([]byte{1, 0, 0, 0})
	copy(page[4096-profile.HMACSize:], mac.Sum(nil))
	return databasePage{salt: saltHex, data: page}
}

func encryptedDatabasePageAt(t *testing.T, keyHex, saltHex, path string) databasePage {
	t.Helper()
	page := encryptedDatabasePage(t, keyHex, saltHex)
	page.path = path
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
	page := encryptedDatabasePage(t, hex.EncodeToString(encKey), saltHex)
	macSalt := make([]byte, len(salt))
	for index := range salt {
		macSalt[index] = salt[index] ^ 0x3a
	}
	macKey := pbkdf2SHA512(encKey, macSalt, 2, nil)
	mac := hmac.New(sha512.New, macKey)
	_, _ = mac.Write(page.data[16:4032])
	_, _ = mac.Write([]byte{1, 0, 0, 0})
	copy(page.data[4032:4096], mac.Sum(nil))
	page.path = "message/message_0.db"
	return page
}

func TestNewCandidateCollectorDoesNotRewriteSharedTargetPages(t *testing.T) {
	salt := strings.Repeat("ab", 16)
	targets := databaseTargets{
		bySalt: map[string][]string{salt: {"contact.db"}},
		pages:  []databasePage{{salt: salt}},
		count:  1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	if targets.pages[0].path != "" || collector.targets.pages[0].path != "" {
		t.Fatal("collector constructor rewrote the caller-owned target page slice")
	}
}

func TestDatabasePatternMapsRawKeyBySalt(t *testing.T) {
	salt := strings.Repeat("ab", 16)
	key := strings.Repeat("12", 32)
	targets := databaseTargets{
		bySalt: map[string][]string{salt: {"contact\\contact.db"}},
		pages:  []databasePage{encryptedDatabasePageAt(t, key, salt, "contact\\contact.db")},
		count:  1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.scan([]byte("prefix-x'" + key + salt + "'-suffix"))

	keys, ambiguous := collector.databaseKeys(targets)
	if ambiguous != 0 || keys["contact\\contact.db"] != key {
		t.Fatalf("unexpected result: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestDatabasePatternMaps64HexKeyAcrossDatabaseSalts(t *testing.T) {
	key := strings.Repeat("34", 32)
	salt1 := strings.Repeat("ab", 16)
	salt2 := strings.Repeat("cd", 16)
	targets := databaseTargets{
		bySalt: map[string][]string{salt1: {"one.db"}, salt2: {"two.db"}},
		pages: []databasePage{
			encryptedDatabasePageAt(t, key, salt1, "one.db"),
			encryptedDatabasePageAt(t, key, salt2, "two.db"),
		},
		count: 2,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.scan([]byte("prefix-x'" + key + "'-suffix"))

	keys, ambiguous := collector.databaseKeys(targets)
	if ambiguous != 0 || keys["one.db"] != key || keys["two.db"] != key {
		t.Fatalf("unexpected result: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestLongDatabasePatternUsesFirstKeyAndLastSalt(t *testing.T) {
	key := strings.Repeat("56", 32)
	salt := strings.Repeat("ef", 16)
	targets := databaseTargets{
		bySalt: map[string][]string{salt: {"message.db"}},
		pages:  []databasePage{encryptedDatabasePageAt(t, key, salt, "message.db")},
		count:  1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.scan([]byte("x'" + key + strings.Repeat("90", 16) + salt + "'"))

	keys, ambiguous := collector.databaseKeys(targets)
	if ambiguous != 0 || keys["message.db"] != key {
		t.Fatalf("unexpected result: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestWrongDatabaseKeyIsRejected(t *testing.T) {
	salt := strings.Repeat("ab", 16)
	validKey := strings.Repeat("12", 32)
	wrongKey := strings.Repeat("34", 32)
	targets := databaseTargets{
		bySalt: map[string][]string{salt: {"contact.db"}},
		pages:  []databasePage{encryptedDatabasePageAt(t, validKey, salt, "contact.db")},
		count:  1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.scan([]byte("x'" + wrongKey + salt + "'"))

	keys, ambiguous := collector.databaseKeys(targets)
	if len(keys) != 0 || ambiguous != 0 {
		t.Fatalf("wrong candidate was accepted: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestDifferentKeysForSameProfileAreValidatorConflict(t *testing.T) {
	targets := databaseTargets{
		pages: []databasePage{{path: "message.db", profileID: defaultProfileID}}, count: 1,
		catalog: databaseCatalog{Databases: []catalogDatabase{{
			DatabaseID: "db", RelativePath: "message.db", RequiredForKeyCoverage: true,
		}}},
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.addDatabaseCandidate("message.db", strings.Repeat("a", 64), defaultProfileID, "raw_enc_key")
	collector.addDatabaseCandidate("message.db", strings.Repeat("b", 64), defaultProfileID, "global_passphrase")
	keys, ambiguous := collector.databaseKeys(targets)
	diag := diagnostics{}
	collector.applyScanDiagnostics(&diag, keys, ambiguous, nil, mediaEvidence{})
	finalizeDiagnostics(&diag, targets, response{DatabaseKeys: keys}, acquireOptions{database: true, budget: unlimitedBudget()})
	if diag.ValidatorConflictCount != 1 || diag.ResultCode != "failed" || diag.WorkflowStatus != "blocked" ||
		len(diag.BlockingReasons) != 1 || diag.BlockingReasons[0] != "validator_conflict" {
		t.Fatalf("same-profile validator conflict was treated as ordinary ambiguity: %+v", diag)
	}
}

func TestDifferentKeysAcrossProfilesAreValidatorConflict(t *testing.T) {
	targets := databaseTargets{
		pages: []databasePage{{path: "message.db"}}, count: 1,
		catalog: databaseCatalog{Databases: []catalogDatabase{{
			DatabaseID: "db", RelativePath: "message.db", RequiredForKeyCoverage: true,
		}}},
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.addDatabaseCandidate("message.db", strings.Repeat("a", 64), "profile-a", "raw_enc_key")
	collector.addDatabaseCandidate("message.db", strings.Repeat("b", 64), "profile-b", "global_passphrase")
	keys, ambiguous := collector.databaseKeys(targets)
	diag := diagnostics{}
	collector.applyScanDiagnostics(&diag, keys, ambiguous, nil, mediaEvidence{})
	finalizeDiagnostics(&diag, targets, response{DatabaseKeys: keys}, acquireOptions{database: true, budget: unlimitedBudget()})
	if diag.ValidatorConflictCount != 1 || diag.ResultCode != "failed" || diag.WorkflowStatus != "blocked" ||
		len(diag.BlockingReasons) != 1 || diag.BlockingReasons[0] != "validator_conflict" {
		t.Fatalf("cross-profile validator conflict was treated as ordinary ambiguity: %+v", diag)
	}
}

func TestV4DatabaseKeyObjectPointers(t *testing.T) {
	pointer := uint64(0x1234567890)
	memory := append([]byte("prefix--"), make([]byte, 8)...)
	binary.LittleEndian.PutUint64(memory[len(memory)-8:], pointer)
	memory = append(memory, v4DatabaseKeyObjectPrefix...)
	capacity := make([]byte, 8)
	binary.LittleEndian.PutUint64(capacity, 47)
	memory = append(memory, capacity...)
	memory = append(memory, []byte("--suffix")...)

	objects := v4DatabaseKeyObjects(memory)
	if len(objects) != 1 || objects[0].pointer != pointer || objects[0].capacity != 47 {
		t.Fatalf("unexpected key objects: %v", objects)
	}
}

func TestV4InternalXORKeyInstructionPattern(t *testing.T) {
	memory := []byte("prefix")
	want := make([]byte, 0, 32)
	for part := byte(1); part <= 4; part++ {
		memory = append(memory, 0x48, 0xba)
		chunk := bytes.Repeat([]byte{part}, 8)
		memory = append(memory, chunk...)
		want = append(want, chunk...)
		memory = append(memory, 0x90, 0x90, 0x90)
	}
	memory = append(memory, 0x48, 0x85, 0xc0)

	keys := v4InternalXORKeys(memory)
	if len(keys) != 1 || !bytes.Equal(keys[0], want) {
		t.Fatalf("unexpected internal XOR keys: %x", keys)
	}
}

func TestXORPassphraseCandidates(t *testing.T) {
	collector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{}}, mediaEvidence{})
	collector.internalXORKeys = [][]byte{bytes.Repeat([]byte{0x55}, 32)}
	candidates := collector.xorPassphraseCandidates([][]byte{bytes.Repeat([]byte{0xaa}, 32)})
	if len(candidates) != 1 || !bytes.Equal(candidates[0], bytes.Repeat([]byte{0xff}, 32)) {
		t.Fatalf("unexpected transformed candidates: %x", candidates)
	}
}

func TestBinaryDatabaseKeyCandidateMustValidatePage(t *testing.T) {
	keyBytes := make([]byte, 32)
	for index := range keyBytes {
		keyBytes[index] = byte(index)
	}
	key := hex.EncodeToString(keyBytes)
	salt := strings.Repeat("9a", 16)
	targets := databaseTargets{
		bySalt: map[string][]string{salt: {"message.db"}},
		pages:  []databasePage{encryptedDatabasePageAt(t, key, salt, "message.db")},
		count:  1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.considerBinaryDatabaseKey(keyBytes, true)

	keys, ambiguous := collector.databaseKeys(targets)
	if ambiguous != 0 || keys["message.db"] != key {
		t.Fatalf("unexpected result: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestCapturedRawDatabaseKeyDoesNotUsePassphraseHeuristic(t *testing.T) {
	key := strings.Repeat("41", 32)
	salt := strings.Repeat("7b", 16)
	page := encryptedDatabasePage(t, key, salt)
	page.path = "message.db"
	targets := databaseTargets{bySalt: map[string][]string{salt: {page.path}}, pages: []databasePage{page}, count: 1}
	collector := newCandidateCollector(targets, mediaEvidence{})
	decoded, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	if !collector.considerCapturedDatabaseKey(decoded) {
		t.Fatal("valid low-entropy-looking raw key was rejected by passphrase heuristics")
	}
	keys, ambiguous := collector.databaseKeys(targets)
	if ambiguous != 0 || keys[page.path] != key {
		t.Fatalf("captured raw key was not retained after HMAC verification: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestMergeValidatedCollectorDoesNotMergeUnverifiedProcessCandidates(t *testing.T) {
	key := strings.Repeat("42", 32)
	salt := strings.Repeat("6c", 16)
	page := encryptedDatabasePage(t, key, salt)
	page.path = "message.db"
	targets := databaseTargets{bySalt: map[string][]string{salt: {page.path}}, pages: []databasePage{page}, count: 1}
	aggregate := newCandidateCollector(targets, mediaEvidence{})
	isolated := newCandidateCollector(targets, mediaEvidence{})
	isolated.binaryCandidates = append(isolated.binaryCandidates, bytes.Repeat([]byte{0x99}, 32))
	decoded, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	if !isolated.considerCapturedDatabaseKey(decoded) {
		t.Fatal("fixture key was not accepted in isolated process collector")
	}
	aggregate.mergeValidatedFrom(isolated)
	if len(aggregate.binaryCandidates) != 0 || len(aggregate.binaryFallbackCandidates) != 0 {
		t.Fatal("unverified process-local candidates crossed the isolation boundary")
	}
	keys, ambiguous := aggregate.databaseKeys(targets)
	if ambiguous != 0 || keys[page.path] != key {
		t.Fatalf("validated candidate did not cross isolation boundary: keys=%v ambiguous=%d", keys, ambiguous)
	}
	if aggregate.validatedDatabaseCandidateCount != isolated.validatedDatabaseCandidateCount {
		t.Fatalf("validated candidate observations were double-counted during isolation merge: aggregate=%d isolated=%d",
			aggregate.validatedDatabaseCandidateCount, isolated.validatedDatabaseCandidateCount)
	}
}

func TestPBKDF2SHA512KnownVector(t *testing.T) {
	derived := pbkdf2SHA512([]byte("password"), []byte("salt"), 1, nil)
	want := "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
	if hex.EncodeToString(derived) != want {
		t.Fatalf("unexpected PBKDF2 result: %x", derived)
	}
	derived = pbkdf2SHA512([]byte("password"), []byte("salt"), 2, nil)
	want = "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
	if hex.EncodeToString(derived) != want {
		t.Fatalf("unexpected iterated PBKDF2 result: %x", derived)
	}
}

func TestV4PassphraseValidatesDatabaseHMAC(t *testing.T) {
	passphrase := strings.Repeat("7b", 32)
	salt := strings.Repeat("4c", 16)
	page := encryptedV4PassphrasePage(t, passphrase, salt)
	passphraseBytes, err := hex.DecodeString(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !validateV4DatabasePassphrase(passphraseBytes, page.data, nil) {
		t.Fatal("valid v4 passphrase was rejected")
	}
	passphraseBytes[0] ^= 0xff
	if validateV4DatabasePassphrase(passphraseBytes, page.data, nil) {
		t.Fatal("wrong v4 passphrase was accepted")
	}
}

func TestMediaAESMustValidateEveryV2Block(t *testing.T) {
	key := "0123456789abcdef"
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte{0xff, 0xd8, 0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var encrypted [16]byte
	block.Encrypt(encrypted[:], plain)
	media := mediaEvidence{v2Blocks: [][16]byte{encrypted}, xorCandidates: map[byte]int{0xf5: 1}}
	collector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{}}, media)
	collector.scan([]byte("prefix:" + key + ":suffix"))

	resolved := collector.resolvedMedia(media)
	if resolved == nil || resolved.AES != key || resolved.XOR != 0xf5 {
		t.Fatalf("unexpected media result: %#v", resolved)
	}
}

func TestAmbiguousDatabaseCandidatesAreRejected(t *testing.T) {
	salt := strings.Repeat("cd", 16)
	key1 := strings.Repeat("11", 32)
	key2 := strings.Repeat("22", 32)
	targets := databaseTargets{
		bySalt: map[string][]string{salt: {"message.db"}},
		pages: []databasePage{
			encryptedDatabasePageAt(t, key1, salt, "message.db"),
			encryptedDatabasePageAt(t, key2, salt, "message.db"),
		},
		count: 1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})
	collector.scan([]byte("x'" + key1 + salt + "'"))
	collector.scan([]byte("x'" + key2 + salt + "'"))

	keys, ambiguous := collector.databaseKeys(targets)
	if len(keys) != 0 || ambiguous != 1 {
		t.Fatalf("ambiguous candidates were accepted: keys=%v ambiguous=%d", keys, ambiguous)
	}
}

func TestCandidateSourcesStopAtTheDocumentedHardCap(t *testing.T) {
	collector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{}}, mediaEvidence{})
	var databaseInput strings.Builder
	for index := 0; index < maxCandidateCount+1; index++ {
		candidate := make([]byte, 32)
		binary.LittleEndian.PutUint64(candidate, uint64(index+1))
		databaseInput.WriteString("x'")
		databaseInput.WriteString(hex.EncodeToString(candidate))
		databaseInput.WriteString("';")
	}
	collector.scanDatabasePatternsFrom([]byte(databaseInput.String()), "bounded_hex")
	if len(collector.seenDatabase) != maxCandidateCount || !collector.databaseScanLimited {
		t.Fatalf("database candidate cap was not enforced: seen=%d limited=%v", len(collector.seenDatabase), collector.databaseScanLimited)
	}

	media := mediaEvidence{v2Blocks: [][16]byte{{}}, xorCandidates: map[byte]int{}}
	mediaCollector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{}}, media)
	var mediaInput strings.Builder
	for index := 0; index < maxMediaCandidateCount+1; index++ {
		fmt.Fprintf(&mediaInput, "%016x:", index)
	}
	mediaCollector.scanMediaPatterns([]byte(mediaInput.String()))
	if len(mediaCollector.seenMedia) != maxMediaCandidateCount || !mediaCollector.mediaScanLimited {
		t.Fatalf("media candidate cap was not enforced: seen=%d limited=%v", len(mediaCollector.seenMedia), mediaCollector.mediaScanLimited)
	}
}
