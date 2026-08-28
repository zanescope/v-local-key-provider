package provider

import (
	"time"

	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

// budget 表示调用方分配给本次取证的时限。
//
// 提供器的内部上限（每进程 2 GiB、总计 6 GiB 扫描，口令候选上限 10,000 且分四组尝试）
// 允许的工作量远超调用方愿意等待的时间：单次口令验证需要 25.6 万轮 PBKDF2-HMAC-SHA512，
// 实测约 164 毫秒，最坏情况合计可达十几分钟。调用方到点直接杀进程，已经完成的部分
// 全部丢失，只剩一句「运行超时」。
//
// 因此首发 v1 就要求请求携带 deadline_ms，提供器据此控制进度，
// 在被杀之前返回已经验证出来的密钥和诊断。
type budget struct{ value workbudget.Budget }

func unlimitedBudget() budget {
	return budget{value: workbudget.Unlimited()}
}

func newBudget(start time.Time, milliseconds int64) budget {
	return budget{value: workbudget.New(start, milliseconds)}
}

func (value budget) cappedAt(deadline time.Time) budget {
	value.value = value.value.CappedAt(deadline)
	return value
}

func (value budget) cappedFor(duration time.Duration) budget {
	value.value = value.value.CappedFor(duration)
	return value
}

func (value budget) withCancellation(done <-chan struct{}) budget {
	value.value = value.value.WithCancellation(done)
	return value
}

func (value budget) expired() bool {
	return value.value.Expired()
}

func (value budget) isUnlimited() bool {
	return value.value.IsUnlimited()
}

func (value budget) deadline() (time.Time, bool) {
	return value.value.Deadline()
}
