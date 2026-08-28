// Package workbudget 持有有界采集工作的 deadline 和取消组合，并且有意不暴露可变表示。
package workbudget

import "time"

// Budget 是按约定不可变的工作限制。派生方法返回的值，其取消存储绝不与源值形成 alias。
type Budget struct {
	deadline      time.Time
	unlimited     bool
	cancellations []<-chan struct{}
}

func Unlimited() Budget {
	return Budget{unlimited: true}
}

func New(start time.Time, milliseconds int64) Budget {
	return Budget{deadline: start.Add(time.Duration(milliseconds) * time.Millisecond)}
}

func (value Budget) CappedAt(deadline time.Time) Budget {
	if value.unlimited || deadline.Before(value.deadline) {
		value.deadline = deadline
		value.unlimited = false
	}
	return value
}

func (value Budget) CappedFor(duration time.Duration) Budget {
	if duration <= 0 {
		return value.CappedAt(time.Now())
	}
	return value.CappedAt(time.Now().Add(duration))
}

func (value Budget) WithCancellation(done <-chan struct{}) Budget {
	if done == nil {
		return value
	}
	cloned := make([]<-chan struct{}, len(value.cancellations), len(value.cancellations)+1)
	copy(cloned, value.cancellations)
	value.cancellations = append(cloned, done)
	return value
}

func (value Budget) Expired() bool {
	if !value.unlimited && !time.Now().Before(value.deadline) {
		return true
	}
	for _, done := range value.cancellations {
		select {
		case <-done:
			return true
		default:
		}
	}
	return false
}

func (value Budget) IsUnlimited() bool {
	return value.unlimited
}

func (value Budget) Deadline() (time.Time, bool) {
	return value.deadline, !value.unlimited
}
