package session

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"

	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
)

const MaxLifetime = 15 * time.Minute

var (
	ErrStoreClosing   = errors.New("acquisition session store is closing")
	ErrAccountActive  = errors.New("目标账号已有 acquisition session 正在运行")
	ErrSessionMissing = errors.New("acquisition session 不存在或已过期")
)

type Record struct {
	ID                string
	AccountDir        string
	DBDir             string
	CatalogKey        []byte
	CatalogID         string
	Scopes            []string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	Receipts          map[string]bool
	ActionAttempts    map[string]int
	Latest            *protocolmodel.Response
	LatestCatalogID   string
	ProcessInstanceID string
	LastRoute         string
	LastActionStage   string
	PlatformSession   any
	Context           context.Context
	Cancel            context.CancelFunc
	InFlight          bool
	ClientIdentity    string
}

type RecordInput struct {
	ID                string
	AccountDir        string
	DBDir             string
	CatalogKey        []byte
	CatalogID         string
	Scopes            []string
	ProcessInstanceID string
	LastActionStage   string
	PlatformSession   any
	ClientIdentity    string
}

type StoreHooks struct {
	SamePath      func(string, string) bool
	CloneSecret   func([]byte) []byte
	ClearSecret   func([]byte)
	ClosePlatform func(any)
}

type Store struct {
	mu       sync.Mutex
	sessions map[string]*Record
	now      func() time.Time
	hooks    StoreHooks
	closing  bool
}

func NewStore(hooks StoreHooks) *Store {
	if hooks.SamePath == nil {
		hooks.SamePath = func(left, right string) bool { return left == right }
	}
	if hooks.CloneSecret == nil {
		hooks.CloneSecret = func(value []byte) []byte { return append([]byte(nil), value...) }
	}
	if hooks.ClearSecret == nil {
		hooks.ClearSecret = clearBytes
	}
	return &Store{sessions: map[string]*Record{}, now: time.Now, hooks: hooks}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func CloneResponse(value *protocolmodel.Response) *protocolmodel.Response {
	if value == nil {
		return nil
	}
	clone := *value
	clone.CatalogEntries = append(value.CatalogEntries[:0:0], value.CatalogEntries...)
	clone.DatabaseKeys = cloneStringMap(value.DatabaseKeys)
	clone.DatabaseProfiles = cloneStringMap(value.DatabaseProfiles)
	clone.DatabaseCredential = CloneDatabaseCredential(value.DatabaseCredential)
	if value.ImageKeys != nil {
		imageKeys := *value.ImageKeys
		clone.ImageKeys = &imageKeys
	}
	clone.Profiles = append(value.Profiles[:0:0], value.Profiles...)
	clone.Diagnostics = cloneDiagnostics(value.Diagnostics)
	return &clone
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

func cloneDiagnostics(value diagnosticmodel.Diagnostics) diagnosticmodel.Diagnostics {
	clone := value
	// 诊断协议区分显式空数组与 null；会话往返时必须保留这一语义。
	clone.RequestedScopes = cloneStringSlice(value.RequestedScopes)
	clone.RoutePriority = cloneStringSlice(value.RoutePriority)
	clone.BlockingReasons = cloneStringSlice(value.BlockingReasons)
	clone.CandidateSources = cloneStringSlice(value.CandidateSources)
	clone.MissingDatabaseIDs = cloneStringSlice(value.MissingDatabaseIDs)
	clone.RoutesAttempted = cloneStringSlice(value.RoutesAttempted)
	clone.StandardRouteEvidence = cloneStringSlice(value.StandardRouteEvidence)
	clone.WindowsRouteEvidence = cloneStringSlice(value.WindowsRouteEvidence)
	if value.PhaseTimingsMS != nil {
		clone.PhaseTimingsMS = make(map[string]int64, len(value.PhaseTimingsMS))
		for key, timing := range value.PhaseTimingsMS {
			clone.PhaseTimingsMS[key] = timing
		}
	}
	if value.FallbackStageCounts != nil {
		clone.FallbackStageCounts = make(map[string]int, len(value.FallbackStageCounts))
		for key, count := range value.FallbackStageCounts {
			clone.FallbackStageCounts[key] = count
		}
	}
	return clone
}

func (store *Store) cloneRecord(record *Record, includeSensitive bool) *Record {
	if record == nil {
		return nil
	}
	clone := *record
	clone.Scopes = append([]string(nil), record.Scopes...)
	clone.Receipts = make(map[string]bool, len(record.Receipts))
	for key, value := range record.Receipts {
		clone.Receipts[key] = value
	}
	clone.ActionAttempts = make(map[string]int, len(record.ActionAttempts))
	for key, value := range record.ActionAttempts {
		clone.ActionAttempts[key] = value
	}
	clone.Latest = CloneResponse(record.Latest)
	clone.Cancel = nil
	if includeSensitive {
		clone.CatalogKey = store.hooks.CloneSecret(record.CatalogKey)
	} else {
		clone.CatalogKey = nil
		clone.PlatformSession = nil
	}
	return &clone
}

func (store *Store) clock() time.Time {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.now()
}

func (store *Store) SetClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	store.mu.Lock()
	store.now = now
	store.mu.Unlock()
}

func (store *Store) Accepting() bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	return !store.closing
}

func (store *Store) NewRecord(input RecordInput) *Record {
	now := store.clock()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(MaxLifetime))
	return &Record{
		ID: input.ID, AccountDir: input.AccountDir, DBDir: input.DBDir,
		CatalogKey: store.hooks.CloneSecret(input.CatalogKey), CatalogID: input.CatalogID,
		Scopes: append([]string(nil), input.Scopes...), CreatedAt: now, ExpiresAt: now.Add(MaxLifetime),
		Receipts: map[string]bool{}, ActionAttempts: map[string]int{},
		ProcessInstanceID: input.ProcessInstanceID, LastActionStage: input.LastActionStage,
		PlatformSession: input.PlatformSession, Context: ctx, Cancel: cancel, ClientIdentity: input.ClientIdentity,
	}
}

func (store *Store) cleanupRecord(record *Record) {
	if record == nil {
		return
	}
	if record.Cancel != nil {
		record.Cancel()
		record.Cancel = nil
	}
	store.hooks.ClearSecret(record.CatalogKey)
	record.CatalogKey = nil
	if record.Latest != nil {
		record.Latest.DatabaseKeys = nil
		record.Latest.DatabaseProfiles = nil
		record.Latest.DatabaseCredential = nil
		record.Latest.ImageKeys = nil
		record.Latest = nil
	}
	if record.PlatformSession != nil && store.hooks.ClosePlatform != nil {
		store.hooks.ClosePlatform(record.PlatformSession)
	}
	record.PlatformSession = nil
}

func (store *Store) Discard(record *Record) {
	store.cleanupRecord(record)
}

func (store *Store) deleteLocked(id string) {
	record := store.sessions[id]
	if record == nil {
		return
	}
	store.cleanupRecord(record)
	delete(store.sessions, id)
}

func (store *Store) cleanupExpiredLocked() {
	now := store.now()
	for id, record := range store.sessions {
		if !now.Before(record.ExpiresAt) {
			store.deleteLocked(id)
		}
	}
}

func (store *Store) Insert(record *Record) error {
	if record == nil || record.ID == "" {
		return errors.New("acquisition session record 无效")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closing {
		return ErrStoreClosing
	}
	store.cleanupExpiredLocked()
	if store.sessions[record.ID] != nil {
		return errors.New("acquisition session id 重复")
	}
	for _, existing := range store.sessions {
		if store.hooks.SamePath(existing.AccountDir, record.AccountDir) {
			return ErrAccountActive
		}
	}
	store.sessions[record.ID] = record
	return nil
}

func (store *Store) ActiveCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked()
	return len(store.sessions)
}

func (store *Store) Has(id string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked()
	return store.sessions[id] != nil
}

func (store *Store) Snapshot(id string) *Record {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked()
	return store.cloneRecord(store.sessions[id], false)
}

// ReleaseSnapshot 清理可变敏感副本，但不取消或关闭 snapshot 引用的活跃 session 资源。
func (store *Store) ReleaseSnapshot(snapshot *Record) {
	if snapshot == nil {
		return
	}
	store.hooks.ClearSecret(snapshot.CatalogKey)
	snapshot.CatalogKey = nil
	if snapshot.Latest != nil {
		snapshot.Latest.DatabaseKeys = nil
		snapshot.Latest.DatabaseProfiles = nil
		snapshot.Latest.DatabaseCredential = nil
		snapshot.Latest.ImageKeys = nil
		snapshot.Latest = nil
	}
	snapshot.PlatformSession = nil
	snapshot.Context = nil
}

// Mutate 在持有 store lock 时执行短暂状态转换。callback 不得执行 I/O，也不得调用
// acquisition/platform 代码。
func (store *Store) Mutate(id string, mutate func(*Record)) bool {
	if mutate == nil {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked()
	record := store.sessions[id]
	if record == nil {
		return false
	}
	mutate(record)
	return true
}

func (store *Store) Delete(id string) bool {
	if id == "" {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked()
	if store.sessions[id] == nil {
		return false
	}
	store.deleteLocked(id)
	return true
}

func (store *Store) CloseAll() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.closing = true
	for id := range store.sessions {
		store.deleteLocked(id)
	}
}

type BeginStatus string

const (
	BeginReady           BeginStatus = "ready"
	BeginCancelled       BeginStatus = "cancelled"
	BeginCatalogDrift    BeginStatus = "catalog_drift"
	BeginInFlight        BeginStatus = "in_flight"
	BeginWaitingReceipt  BeginStatus = "waiting_receipt"
	BeginReceiptRejected BeginStatus = "receipt_rejected"
	BeginDuplicate       BeginStatus = "duplicate_receipt"
	BeginRetryExhausted  BeginStatus = "retry_exhausted"
)

type BeginInput struct {
	SessionID                string
	AccountDir               string
	DBDir                    string
	Scopes                   []string
	ClientIdentity           string
	Operation                string
	ExpectedCatalogID        string
	ActionReceipt            *protocolmodel.ActionReceipt
	CurrentProcessInstanceID string
}

type BeginResult struct {
	Status               BeginStatus
	Session              *Record
	FinishCurrentPartial bool
}

func (store *Store) Begin(input BeginInput) (BeginResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanupExpiredLocked()
	record := store.sessions[input.SessionID]
	if record == nil {
		return BeginResult{}, ErrSessionMissing
	}
	if !store.hooks.SamePath(record.AccountDir, input.AccountDir) ||
		!store.hooks.SamePath(record.DBDir, input.DBDir) || !SameScopes(record.Scopes, input.Scopes) {
		return BeginResult{}, errors.New("acquisition session 账号或数据库目录不匹配")
	}
	if record.ClientIdentity != input.ClientIdentity {
		return BeginResult{}, errors.New("acquisition session 客户端身份不匹配")
	}
	if input.Operation == "cancel" {
		snapshot := store.cloneRecord(record, false)
		store.deleteLocked(record.ID)
		return BeginResult{Status: BeginCancelled, Session: snapshot}, nil
	}
	if input.ExpectedCatalogID == "" {
		return BeginResult{}, errors.New("observe/finalize 必须绑定 expected_catalog_id")
	}
	if input.ExpectedCatalogID != record.CatalogID {
		return BeginResult{Status: BeginCatalogDrift, Session: store.cloneRecord(record, false)}, nil
	}
	if record.InFlight {
		return BeginResult{Status: BeginInFlight, Session: store.cloneRecord(record, false)}, nil
	}
	finishCurrentPartial := input.Operation == "finalize" && input.ActionReceipt == nil && IsPartialFinalizeAction(record.LastActionStage)
	if IsAction(record.LastActionStage) && input.ActionReceipt == nil && !finishCurrentPartial {
		return BeginResult{Status: BeginWaitingReceipt, Session: store.cloneRecord(record, false)}, nil
	}
	fingerprint, err := ReceiptFingerprint(input.ActionReceipt, ReceiptState{
		CatalogID: record.CatalogID, ProcessInstanceID: record.ProcessInstanceID,
		LastRoute: record.LastRoute, LastActionStage: record.LastActionStage,
	}, input.CurrentProcessInstanceID)
	if err != nil {
		return BeginResult{Status: BeginReceiptRejected, Session: store.cloneRecord(record, false)}, nil
	}
	if fingerprint != "" && record.Receipts[fingerprint] {
		return BeginResult{Status: BeginDuplicate, Session: store.cloneRecord(record, false)}, nil
	}
	if fingerprint != "" {
		limit := ActionRetryLimit(input.ActionReceipt.Action)
		if limit == 0 || record.ActionAttempts[input.ActionReceipt.Action] >= limit {
			return BeginResult{Status: BeginRetryExhausted, Session: store.cloneRecord(record, false)}, nil
		}
		if record.ActionAttempts == nil {
			record.ActionAttempts = map[string]int{}
		}
		if record.Receipts == nil {
			record.Receipts = map[string]bool{}
		}
		record.Receipts[fingerprint] = true
		record.ActionAttempts[input.ActionReceipt.Action]++
	}
	record.InFlight = true
	return BeginResult{Status: BeginReady, Session: store.cloneRecord(record, true), FinishCurrentPartial: finishCurrentPartial}, nil
}

func (store *Store) FinishRequest(id string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if record := store.sessions[id]; record != nil {
		record.InFlight = false
	}
}

type CommitInput struct {
	Latest            protocolmodel.Response
	LatestCatalogID   string
	ProcessInstanceID string
	LastRoute         string
	LastActionStage   string
	Delete            bool
}

func (store *Store) Commit(id string, input CommitInput) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.sessions[id]
	if record == nil {
		return false
	}
	if input.Delete {
		store.deleteLocked(id)
		return true
	}
	record.Latest = CloneResponse(&input.Latest)
	record.LatestCatalogID = input.LatestCatalogID
	record.ProcessInstanceID = input.ProcessInstanceID
	record.LastRoute = input.LastRoute
	record.LastActionStage = input.LastActionStage
	record.InFlight = false
	return true
}
