// Package crypto 包含有界密码学派生和带认证的数据库 page 验证。protocol、catalog、
// credential 和 platform 状态不得进入本 package。
package crypto

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"runtime"
)

const cancellationCheckInterval = 4096

// PBKDF2SHA512Key32 派生 PBKDF2-HMAC-SHA512 的前 32 字节，并以有界间隔检查 cancelled。
// 被取消的派生返回 nil。
func PBKDF2SHA512Key32(password, salt []byte, iterations int, cancelled func() bool) []byte {
	if iterations <= 0 {
		return nil
	}
	blockInput := make([]byte, len(salt)+4)
	copy(blockInput, salt)
	binary.BigEndian.PutUint32(blockInput[len(salt):], 1)
	defer zero(blockInput)

	mac := hmac.New(sha512.New, password)
	_, _ = mac.Write(blockInput)
	u := mac.Sum(nil)
	result := append([]byte(nil), u...)
	defer func() {
		zero(u)
		zero(result)
	}()
	for iteration := 1; iteration < iterations; iteration++ {
		if iteration%cancellationCheckInterval == 0 && cancelled != nil && cancelled() {
			return nil
		}
		mac.Reset()
		_, _ = mac.Write(u)
		u = mac.Sum(u[:0])
		for index := range result {
			result[index] ^= u[index]
		}
	}
	return append([]byte(nil), result[:32]...)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
