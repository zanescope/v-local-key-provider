package provider

import (
	"testing"
	"time"
)

func TestAcquisitionPlatformSessionCollectStatusAndCloseAreBounded(t *testing.T) {
	closed := 0
	session := newSynchronizedPlatformSession(
		func(*candidateCollector) platformHookSnapshot {
			return platformHookSnapshot{Installed: true, Captures: 2}
		},
		func() platformHookSnapshot { return platformHookSnapshot{TargetFound: 1} },
		func() { closed++ },
	)
	if result := session.Collect(nil); !result.Installed || result.Captures != 2 {
		t.Fatalf("collect result was lost: %+v", result)
	}
	if result := session.Status(); result.TargetFound != 1 {
		t.Fatalf("status result was lost: %+v", result)
	}
	session.Close()
	session.Close()
	if closed != 1 || session.Collect(nil) != (platformHookSnapshot{}) || session.Status() != (platformHookSnapshot{}) {
		t.Fatalf("closed session remained usable or closed twice: closed=%d", closed)
	}
}

func TestCancelSessionRemovesSecretsAndPlatformState(t *testing.T) {
	store := newTestAcquisitionSessionStore(t)
	closed := 0
	record := &acquisitionSession{
		ID: "session", CatalogKey: []byte{1, 2, 3}, PlatformSession: newSynchronizedPlatformSession(nil, nil, func() { closed++ }),
		Latest: &response{DatabaseKeys: map[string]string{"db": "secret"}}, ExpiresAt: time.Now().Add(time.Minute),
		Receipts: map[string]bool{}, ActionAttempts: map[string]int{},
	}
	if err := store.core.Insert(record); err != nil {
		t.Fatal(err)
	}
	store.cancelSession("session")
	if store.activeCount() != 0 || closed != 1 {
		t.Fatalf("cancel did not remove session state: sessions=%d closed=%d", store.activeCount(), closed)
	}
}
