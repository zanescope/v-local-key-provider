package provider

import (
	"testing"
	"time"
)

func TestAcquisitionPlatformSessionCollectStatusAndCloseAreBounded(t *testing.T) {
	closed := 0
	session := &synchronizedPlatformSession{
		collectFn: func(*candidateCollector) platformHookSnapshot {
			return platformHookSnapshot{Installed: true, Captures: 2}
		},
		statusFn: func() platformHookSnapshot { return platformHookSnapshot{TargetFound: 1} },
		closeFn:  func() { closed++ },
	}
	if result := session.collect(nil); !result.Installed || result.Captures != 2 {
		t.Fatalf("collect result was lost: %+v", result)
	}
	if result := session.status(); result.TargetFound != 1 {
		t.Fatalf("status result was lost: %+v", result)
	}
	session.close()
	session.close()
	if closed != 1 || session.collect(nil) != (platformHookSnapshot{}) || session.status() != (platformHookSnapshot{}) {
		t.Fatalf("closed session remained usable or closed twice: closed=%d", closed)
	}
}

func TestCancelSessionRemovesSecretsAndPlatformState(t *testing.T) {
	store := newAcquisitionSessionStore()
	closed := 0
	record := &acquisitionSession{
		ID: "session", CatalogKey: []byte{1, 2, 3}, PlatformSession: &synchronizedPlatformSession{closeFn: func() { closed++ }},
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

func TestCandidateCollectorClearsMutableSecretBuffers(t *testing.T) {
	first := []byte{1, 2, 3}
	second := []byte{4, 5, 6}
	passphrase := []byte{7, 8, 9}
	collector := newCandidateCollector(databaseTargets{}, mediaEvidence{})
	collector.binaryCandidates = [][]byte{first}
	collector.internalXORKeys = [][]byte{second}
	collector.globalPassphrases["passphrase"] = &globalPassphraseEvidence{secret: passphrase}
	collector.clearSensitiveBuffers()
	for _, values := range [][]byte{first, second, passphrase} {
		for _, value := range values {
			if value != 0 {
				t.Fatalf("mutable candidate buffer was not cleared: first=%v second=%v passphrase=%v", first, second, passphrase)
			}
		}
	}
}
