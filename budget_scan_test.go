package main

import (
	"testing"
	"time"
)

// 构造一批不可能命中的假口令候选。若不检查时限，每个都要跑满 25.6 万轮
// PBKDF2（实测约 164 毫秒）；已过期的预算必须让整个口令暴力过程近乎立即返回。
func fakePassphraseCandidates(count int) [][]byte {
	candidates := make([][]byte, count)
	for index := range candidates {
		key := make([]byte, 32)
		for position := range key {
			key[position] = byte(index*7 + position*3 + 1)
		}
		candidates[index] = key
	}
	return candidates
}

func fakeDatabasePage() databasePage {
	// 4096 字节全零页：解不出任何有效 SQLCipher 头，保证不会误命中。
	return databasePage{salt: "00000000000000000000000000000000", data: make([]byte, 4096)}
}

func TestFindV4PassphraseHonorsExpiredBudget(t *testing.T) {
	candidates := fakePassphraseCandidates(2000) // 无时限时约 2000 × 164ms ≈ 5 分钟
	page := fakeDatabasePage()

	expired := newBudget(time.Now().Add(-time.Second), 100)
	start := time.Now()
	found, tested := findV4DatabasePassphrase(candidates, page, expired)
	elapsed := time.Since(start)

	if found != nil {
		t.Fatal("全零页不应解出口令")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("已过期预算未能让口令暴力短路：耗时 %v，验证了 %d 个候选", elapsed, tested)
	}
	t.Logf("已过期预算下 %v 内返回，仅验证 %d/%d 个候选", elapsed, tested, len(candidates))
}

func TestResolveDatabasePassphraseHonorsExpiredBudget(t *testing.T) {
	collector := newCandidateCollector(
		databaseTargets{
			bySalt: map[string][]string{"00000000000000000000000000000000": {"message_0.db"}},
			pages:  []databasePage{fakeDatabasePage()},
		},
		mediaEvidence{},
	)
	collector.binaryCandidates = fakePassphraseCandidates(2000)

	expired := newBudget(time.Now().Add(-time.Second), 100)
	start := time.Now()
	collector.resolveDatabasePassphrase(expired)
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("已过期预算未能让口令解析短路：耗时 %v", elapsed)
	}
	if !collector.databaseScanLimited {
		t.Fatal("预算耗尽时应标记 databaseScanLimited")
	}
}

// 反向保证：时限充足时口令验证照常进行，不被预算逻辑误伤。
func TestFindV4PassphraseRunsWithAmpleBudget(t *testing.T) {
	candidates := fakePassphraseCandidates(4)
	page := fakeDatabasePage()

	ample := newBudget(time.Now(), 60_000)
	_, tested := findV4DatabasePassphrase(candidates, page, ample)
	if tested != len(candidates) {
		t.Fatalf("时限充足时应验证全部候选，实际只验证了 %d/%d", tested, len(candidates))
	}
}
