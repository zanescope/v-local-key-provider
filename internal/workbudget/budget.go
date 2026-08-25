// Package workbudget owns deadline and cancellation composition for bounded
// acquisition work. It deliberately exposes no mutable representation.
package workbudget

import "time"

// Budget is an immutable-by-convention work limit. Derivation methods return a
// value whose cancellation storage never aliases the source value.
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
