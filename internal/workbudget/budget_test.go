package workbudget

import (
	"testing"
	"time"
)

func TestDerivedCancellationStorageDoesNotAlias(t *testing.T) {
	seed := make(chan struct{})
	base := New(time.Now(), time.Minute.Milliseconds())
	base.cancellations = make([]<-chan struct{}, 1, 4)
	base.cancellations[0] = seed
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	first := base.WithCancellation(firstDone)
	second := base.WithCancellation(secondDone)
	close(firstDone)
	if !first.Expired() || second.Expired() {
		t.Fatal("derived budgets shared cancellation state")
	}
}

func TestEarlierCapWins(t *testing.T) {
	value := Unlimited().CappedAt(time.Now().Add(-time.Millisecond))
	if value.IsUnlimited() || !value.Expired() {
		t.Fatal("deadline cap did not replace unlimited budget")
	}
}
