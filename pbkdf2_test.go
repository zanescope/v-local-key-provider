package main

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"
)

// 手写 pbkdf2SHA512 承载了标准库不提供的取消钩子，因此不能替换。但它的密钥派生
// 结果必须与标准库逐字节一致，否则历史上验证出的口令会失配。这个测试把两者钉在一起。
func TestPBKDF2MatchesStdlib(t *testing.T) {
	cases := []struct {
		password, salt string
		iterations     int
	}{
		{"", "", 1},
		{"password", "salt", 1},
		{"password", "salt", 4096},
		{"0102030405060708090a0b0c0d0e0f10", "abcdefghijklmnop", v4KDFIterations},
		{"短口令", "0123456789abcdef", 2},
	}
	for _, testCase := range cases {
		none := &atomic.Bool{}
		mine := pbkdf2SHA512([]byte(testCase.password), []byte(testCase.salt), testCase.iterations, none)
		// 标准库输出 64 字节（SHA-512 一个块），手写版截断到 32；只比对前 32 字节。
		theirs, err := pbkdf2.Key(sha512.New, testCase.password, []byte(testCase.salt), testCase.iterations, 32)
		if err != nil {
			t.Fatalf("标准库返回错误：%v", err)
		}
		if !bytes.Equal(mine, theirs) {
			t.Errorf("KDF 输出不一致 password=%q iter=%d\n  手写=%s\n  标准库=%s",
				testCase.password, testCase.iterations,
				hex.EncodeToString(mine), hex.EncodeToString(theirs))
		}
	}
}

// 取消钩子是保留手写实现的唯一理由，用测试固定它确实生效：已取消时必须提前返回。
func TestPBKDF2CancellationShortCircuits(t *testing.T) {
	password := make([]byte, 32)
	salt := make([]byte, 16)

	cancelled := &atomic.Bool{}
	cancelled.Store(true)
	start := time.Now()
	pbkdf2SHA512(password, salt, v4KDFIterations, cancelled)
	cancelledElapsed := time.Since(start)

	full := &atomic.Bool{}
	start = time.Now()
	pbkdf2SHA512(password, salt, v4KDFIterations, full)
	fullElapsed := time.Since(start)

	// 已取消的派生应远快于跑满 25.6 万轮；给一个宽松但有意义的上界。
	if cancelledElapsed*5 > fullElapsed {
		t.Fatalf("取消钩子未有效短路：已取消 %v，跑满 %v", cancelledElapsed, fullElapsed)
	}
}
