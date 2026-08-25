package provider

import (
	"sync"

	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
)

type platformHookSnapshot = platformmodel.HookSnapshot

type acquisitionPlatformSession interface {
	collect(*candidateCollector) platformHookSnapshot
	status() platformHookSnapshot
	close()
}

type synchronizedPlatformSession struct {
	mu        sync.Mutex
	collectFn func(*candidateCollector) platformHookSnapshot
	statusFn  func() platformHookSnapshot
	closeFn   func()
	closed    bool
}

func (session *synchronizedPlatformSession) collect(collector *candidateCollector) platformHookSnapshot {
	if session == nil {
		return platformHookSnapshot{}
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.collectFn == nil {
		return platformHookSnapshot{}
	}
	return session.collectFn(collector)
}

func (session *synchronizedPlatformSession) status() platformHookSnapshot {
	if session == nil {
		return platformHookSnapshot{}
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.statusFn == nil {
		return platformHookSnapshot{}
	}
	return session.statusFn()
}

func (session *synchronizedPlatformSession) close() {
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
