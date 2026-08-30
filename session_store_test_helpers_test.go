package provider

import (
	"testing"

	acquisitionmodel "github.com/zanescope/v-local-key-provider/internal/acquisition"
	sessionmodel "github.com/zanescope/v-local-key-provider/internal/session"
)

// newInertAcquisitionSessionStore keeps policy and daemon tests off the live
// platform route. Those tests exercise coordinator state, not process capture.
func inertAcquisitionSessionRuntime() sessionmodel.Runtime {
	runtime := acquisitionSessionRuntime()
	runtime.PreparePlatformSession = func(acquisitionmodel.Targets, sessionmodel.Options) acquisitionmodel.PlatformSession {
		return nil
	}
	runtime.ProcessInstanceID = func() string { return "test-process-instance" }
	return runtime
}

func newInertAcquisitionSessionStore() *acquisitionSessionStore {
	return newAcquisitionSessionStoreWithRuntime(inertAcquisitionSessionRuntime())
}

func newTestAcquisitionSessionStore(t *testing.T) *acquisitionSessionStore {
	t.Helper()
	store := newInertAcquisitionSessionStore()
	t.Cleanup(store.closeAll)
	return store
}
