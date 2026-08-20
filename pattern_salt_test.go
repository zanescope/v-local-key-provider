package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestScanSaltNeighborhoodRecoversAdjacentRawKey 验证盐值邻域兜底：内存里只把二进制盐
// 和 raw key 相邻存放、没有 x'<key><salt>' 字面量时，仅靠 scanSaltNeighborhood 也能命中。
func TestScanSaltNeighborhoodRecoversAdjacentRawKey(t *testing.T) {
	salt := strings.Repeat("ab", 16)
	key := strings.Repeat("12", 32)
	targets := databaseTargets{
		bySalt: map[string][]string{salt: {"contact/contact.db"}},
		pages:  []databasePage{encryptedDatabasePage(t, key, salt)},
		count:  1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})

	saltBin, _ := hex.DecodeString(salt)
	keyBin, _ := hex.DecodeString(key)
	var buffer []byte
	buffer = append(buffer, bytes.Repeat([]byte{0x77}, 64)...)
	buffer = append(buffer, saltBin...)
	buffer = append(buffer, bytes.Repeat([]byte{0x33}, 24)...) // 间隔，不构成 x'...' 字面量
	buffer = append(buffer, keyBin...)
	buffer = append(buffer, bytes.Repeat([]byte{0x77}, 64)...)

	collector.scanSaltNeighborhood(buffer)

	keys, ambiguous := collector.databaseKeys(targets)
	if ambiguous != 0 || keys["contact/contact.db"] != key {
		t.Fatalf("盐值邻域未能恢复密钥：keys=%v ambiguous=%d", keys, ambiguous)
	}
}

// TestScanSaltNeighborhoodIgnoresDistantKey 验证密钥落在邻域窗口之外时不会被误纳入。
func TestScanSaltNeighborhoodIgnoresDistantKey(t *testing.T) {
	salt := strings.Repeat("cd", 16)
	key := strings.Repeat("34", 32)
	targets := databaseTargets{
		bySalt: map[string][]string{salt: {"far.db"}},
		pages:  []databasePage{encryptedDatabasePage(t, key, salt)},
		count:  1,
	}
	collector := newCandidateCollector(targets, mediaEvidence{})

	saltBin, _ := hex.DecodeString(salt)
	keyBin, _ := hex.DecodeString(key)
	var buffer []byte
	buffer = append(buffer, saltBin...)
	buffer = append(buffer, bytes.Repeat([]byte{0x33}, saltNeighborhoodWindow+64)...)
	buffer = append(buffer, keyBin...)

	collector.scanSaltNeighborhood(buffer)

	if keys, _ := collector.databaseKeys(targets); len(keys) != 0 {
		t.Fatalf("窗口外的密钥不应被命中：keys=%v", keys)
	}
}

func TestLooksLikeBinaryDatabaseKeyFilters(t *testing.T) {
	if looksLikeBinaryDatabaseKey(make([]byte, 32)) {
		t.Fatal("全零候选必须被拒绝")
	}
	withNulls := bytes.Repeat([]byte{0x11}, 32)
	withNulls[10], withNulls[11] = 0, 0
	if looksLikeBinaryDatabaseKey(withNulls) {
		t.Fatal("含连续 NUL 的候选必须被拒绝")
	}
	if !looksLikeBinaryDatabaseKey(bytes.Repeat([]byte{0x12}, 32)) {
		t.Fatal("类随机密钥应通过")
	}
	if looksLikeBinaryDatabaseKey(make([]byte, 31)) {
		t.Fatal("长度不为 32 必须被拒绝")
	}
}
