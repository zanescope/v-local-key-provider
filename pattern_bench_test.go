package provider

import (
	"crypto/rand"
	"strings"
	"testing"
)

// 这些基准量化内存块级扫描各步骤的吞吐，用来判断 darwin 侧把 scanInternalXORKeys
// 收窄为仅扫描映像（需要为 cgo 内存区域查询补充类型信息）是否划算：只有当它相对基线
// collector.scan 明显更贵时才值得改。随机数据不含 0x48 0xba 标记，测的是无命中时的
// 常态成本；salt 邻域用不在数据里的盐值，测的是最坏情况的全缓冲搜索。
func benchRandom(n int) []byte {
	data := make([]byte, n)
	_, _ = rand.Read(data)
	return data
}

func BenchmarkCollectorScan(b *testing.B) {
	data := benchRandom(1 << 20)
	collector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{}}, mediaEvidence{})
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.scan(data)
	}
}

func BenchmarkScanInternalXORKeys(b *testing.B) {
	data := benchRandom(1 << 20)
	collector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{}}, mediaEvidence{})
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.scanInternalXORKeys(data)
	}
}

func BenchmarkScanSaltNeighborhood(b *testing.B) {
	data := benchRandom(1 << 20)
	salt := strings.Repeat("ab", 16) // 不在随机数据里 → 每块每盐一次全缓冲 bytes.Index（最坏）
	collector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{salt: {"x.db"}}}, mediaEvidence{})
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.scanSaltNeighborhood(data)
	}
}

func BenchmarkV4DatabaseKeyObjects(b *testing.B) {
	data := benchRandom(1 << 20)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v4DatabaseKeyObjects(data)
	}
}
