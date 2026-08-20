package main

import (
	"sync/atomic"
	"testing"
)

// 这些解析器全部作用于微信进程内存与磁盘上的 DAT 文件——其中包含网络收到的内容，
// 属于不可信输入。任何越界或崩溃都会以密钥提取进程的高权限身份发生，因此逐个模糊。

func FuzzV4DatabaseKeyObjects(f *testing.F) {
	f.Add(append(append([]byte{1, 2, 3, 4, 5, 6, 7, 8}, v4DatabaseKeyObjectPrefix...),
		make([]byte, 16)...))
	f.Add([]byte{})
	f.Add(v4DatabaseKeyObjectPrefix)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		for _, object := range v4DatabaseKeyObjects(data) {
			if object.capacity < 32 || object.capacity > 4096 {
				t.Fatalf("返回了越界 capacity=%d", object.capacity)
			}
		}
	})
}

func FuzzV4InternalXORKeys(f *testing.F) {
	f.Add([]byte{0x48, 0xba, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		for _, key := range v4InternalXORKeys(data) {
			if len(key) != 32 {
				t.Fatalf("内部 XOR 密钥长度应为 32，实际 %d", len(key))
			}
		}
	})
}

func FuzzScanDatabasePatterns(f *testing.F) {
	f.Add([]byte(`x'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'`))
	f.Add([]byte(`x'`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		collector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{}}, mediaEvidence{})
		collector.scanDatabasePatterns(data)
	})
}

func FuzzScanMediaPatterns(f *testing.F) {
	f.Add([]byte("0123456789abcdef0123456789abcdef"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<18 {
			t.Skip()
		}
		collector := newCandidateCollector(databaseTargets{bySalt: map[string][]string{}},
			mediaEvidence{v2Blocks: [][16]byte{{}}})
		collector.scanMediaPatterns(data)
	})
}

func FuzzValidateRawDatabaseKey(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 4096))
	f.Fuzz(func(t *testing.T, key, page []byte) {
		if len(page) > 1<<16 {
			t.Skip()
		}
		validateRawDatabaseKey(key, page)
	})
}

func FuzzValidateV4DatabasePassphrase(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 4096))
	f.Fuzz(func(t *testing.T, passphrase, page []byte) {
		if len(page) > 1<<16 || len(passphrase) != 32 {
			t.Skip()
		}
		cancelled := &atomic.Bool{}
		cancelled.Store(true) // 立刻取消，避免每次都跑满 25.6 万轮 KDF
		validateV4DatabasePassphrase(passphrase, page, cancelled)
	})
}

func FuzzInferPrefixXOR(f *testing.F) {
	f.Add([]byte{0xff, 0xd8, 0xff, 0x00}, []byte{0xff, 0xd8, 0xff})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, ciphertext, signature []byte) {
		if len(ciphertext) > 4096 || len(signature) > 64 {
			t.Skip()
		}
		key, ok := inferPrefixXOR(ciphertext, signature)
		// 若声称推断出 XOR 密钥，该密钥必须能把每个密文字节还原成签名字节。
		if ok {
			for index := range signature {
				if ciphertext[index]^key != signature[index] {
					t.Fatalf("推断出的 XOR 密钥不自洽：位置 %d", index)
				}
			}
		}
	})
}
