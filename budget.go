package main

import "time"

// budget 表示调用方分配给本次取证的时限。
//
// 提供器的内部上限（每进程 2 GiB、总计 6 GiB 扫描，口令候选上限 10,000 且分四组尝试）
// 允许的工作量远超调用方愿意等待的时间：单次口令验证需要 25.6 万轮 PBKDF2-HMAC-SHA512，
// 实测约 164 毫秒，最坏情况合计可达十几分钟。调用方到点直接杀进程，已经完成的部分
// 全部丢失，只剩一句「运行超时」。
//
// 因此把时限做进协议：v2 请求携带 deadline_ms，提供器据此自我收敛，
// 在被杀之前返回已经验证出来的密钥和诊断。
type budget struct {
	deadline  time.Time
	unlimited bool
}

// maxBudgetMilliseconds 用于拒绝明显不合理的时限值。
const maxBudgetMilliseconds = 3_600_000

func unlimitedBudget() budget {
	return budget{unlimited: true}
}

func newBudget(start time.Time, milliseconds int64) budget {
	return budget{deadline: start.Add(time.Duration(milliseconds) * time.Millisecond)}
}

func (value budget) expired() bool {
	return !value.unlimited && !time.Now().Before(value.deadline)
}
