package provider

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"

	daemonmodel "github.com/zanescope/v-local-key-provider/internal/daemon"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	shadowmodel "github.com/zanescope/v-local-key-provider/internal/shadow"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowfixture "github.com/zanescope/v-local-key-provider/internal/shadowfixture"
)

type verticalClock struct {
	mu  sync.Mutex
	now uint64
}

func (value *verticalClock) NowNS() (uint64, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.now, nil
}

func (value *verticalClock) Advance(delta uint64) {
	value.mu.Lock()
	value.now += delta
	value.mu.Unlock()
}

func TestSyntheticShadowUsesDaemonFramingAndIndependentCoordinator(t *testing.T) {
	const (
		buildDigest  = "1111111111111111111111111111111111111111111111111111111111111111"
		sourceDigest = "2222222222222222222222222222222222222222222222222222222222222222"
		catalogKey   = "abababababababababababababababababababababababababababababababab"
		accountDir   = "synthetic-account"
		databaseDir  = "synthetic-database"
	)
	decodedKey, err := hex.DecodeString(catalogKey)
	if err != nil {
		t.Fatal(err)
	}
	optionsDigest := catalogHMAC(
		decodedKey, "v-local-shadow-options/v1", accountDir, databaseDir, "media",
	)
	credential := shadowfixture.Credential()
	clock := &verticalClock{now: 1_000_000_000}
	journal := shadowmodel.NewMemoryJournal()
	adapter := &shadowmodel.SyntheticAdapter{
		Clock: clock, AdvanceNS: clock.Advance, StepNS: 1_000_000,
		BuildSet: buildDigest, SourceDigest: sourceDigest, SourceVersion: "4.1.11", SourceBuild: "26000",
		Credential: credential, Expected: credential,
		FailBefore: map[string]string{}, FailAfter: map[string]string{}, AdvanceByStage: map[string]uint64{},
	}
	sequence := 0
	coordinator, err := shadowmodel.NewCoordinator(shadowmodel.Config{
		BuildSetDigest: buildDigest, CleanupRoute: contract.CleanupRouteDirect,
		SyntheticRouteEnabled: true, ExpectedSecurityPosture: "synthetic",
		Clock: clock, Journal: journal, Locker: &shadowmodel.MemoryLocker{}, Adapter: adapter, Cleanup: adapter,
		NewID: func() (string, error) {
			sequence++
			return "abcdefabcdefabcdefabcdefabcdefab", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newTestAcquisitionSessionStore(t)
	store.shadow = coordinator
	service, err := daemonmodel.New(daemonmodel.Config{
		Version: "synthetic-shadow-test", NewBackend: func(daemonmodel.BackendContext) daemonmodel.Backend {
			return daemonmodel.Backend{
				HandleContext: store.handleContext, CancelSession: store.cancelSession,
				ActiveCount: store.activeCount, Close: store.closeAll,
			}
		},
		RuntimeContext: func(advertised string) (bool, string, error) {
			context := daemonmodel.ContextForProvider(advertised)
			return context.HelperMode, context.HelperStatus, nil
		},
		ValidateClientPath: filepath.Abs,
		IsLinkOrReparse:    func(string, fs.FileMode) (bool, error) { return false, nil },
		SamePath:           func(left, right string) bool { return filepath.Clean(left) == filepath.Clean(right) },
		MarkSensitive:      func([]byte) {},
		ZeroSensitive: func(value []byte) {
			for index := range value {
				value[index] = 0
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t0, _ := clock.NowNS()
	deadline := contract.NewDeadline(t0)
	inner := contract.Request{
		Version: contract.Version, Operation: "synthetic_execute",
		RequestID: "9999aaaabbbbccccddddeeeeffff0000", ChallengeID: "00112233445566778899aabbccddeeff",
		BuildSetDigest: buildDigest, SourceQualificationDigest: sourceDigest,
		CleanupRoute: contract.CleanupRouteDirect, AccountBindingID: "aabbccddeeff0011",
		OptionsDigest: optionsDigest, Deadline: &deadline,
	}
	request := protocolmodel.AcquireRequest{
		Protocol: protocolmodel.Name, RequestID: inner.RequestID, Action: "acquire",
		CatalogKey: catalogKey, AccountDir: accountDir, DBDir: databaseDir,
		Scopes: []string{"media"}, DeadlineMS: 120_000,
		Workflow: protocolmodel.WorkflowRequest{Operation: "shadow", Shadow: &inner},
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	var output bytes.Buffer
	if err := service.RunStdio(bytes.NewReader(payload), &output); err != nil {
		t.Fatal(err)
	}
	var response protocolmodel.Response
	if err := json.NewDecoder(&output).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Diagnostics.ShadowAttempt == nil || response.Diagnostics.ShadowAttempt.Status != "ready" ||
		response.ImageKeys == nil || response.ImageKeys.AES != "1234567890abcdef" || response.ImageKeys.XOR != 7 {
		t.Fatalf("synthetic daemon Shadow response was not ready: %+v", response.Diagnostics.ShadowAttempt)
	}
	if adapter.Residue() {
		t.Fatal("synthetic daemon Shadow response returned before Provider cleanup")
	}
	if absent, err := journal.Absent(); err != nil || !absent {
		t.Fatalf("synthetic daemon Shadow retained recovery state: absent=%v err=%v", absent, err)
	}
}
