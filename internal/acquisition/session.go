package acquisition

import (
	"sync"

	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
)

type synchronizedPlatformSession struct {
	mu        sync.Mutex
	collectFn func(*Collector) platformmodel.HookSnapshot
	statusFn  func() platformmodel.HookSnapshot
	closeFn   func()
	closed    bool
}

func NewSynchronizedPlatformSession(
	collectFn func(*Collector) platformmodel.HookSnapshot,
	statusFn func() platformmodel.HookSnapshot,
	closeFn func(),
) PlatformSession {
	return &synchronizedPlatformSession{collectFn: collectFn, statusFn: statusFn, closeFn: closeFn}
}

func (session *synchronizedPlatformSession) Collect(collector *Collector) platformmodel.HookSnapshot {
	if session == nil {
		return platformmodel.HookSnapshot{}
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.collectFn == nil {
		return platformmodel.HookSnapshot{}
	}
	return session.collectFn(collector)
}

func (session *synchronizedPlatformSession) Status() platformmodel.HookSnapshot {
	if session == nil {
		return platformmodel.HookSnapshot{}
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.statusFn == nil {
		return platformmodel.HookSnapshot{}
	}
	return session.statusFn()
}

func (session *synchronizedPlatformSession) Close() {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return
	}
	session.closed = true
	if session.closeFn != nil {
		session.closeFn()
	}
}
