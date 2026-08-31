package shadow

import (
	"context"
	"errors"
	"sync"

	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
)

var ErrNoRecoveryRecord = errors.New("no shadow recovery record")

type Journal interface {
	Load() (RecoveryRecord, error)
	Save(RecoveryRecord) error
	Binding() (contract.ResourceBinding, error)
	Remove(contract.ResourceBinding) error
	Absent() (bool, error)
}

type Locker interface {
	Acquire(context.Context) (func() error, error)
}

type MemoryJournal struct {
	Record        *RecoveryRecord
	RecordBinding contract.ResourceBinding
	History       []RecoveryRecord
	SaveCount     int
	RemoveCount   int
	FailSaveAt    int
	FailRemove    bool
}

func NewMemoryJournal() *MemoryJournal {
	return &MemoryJournal{RecordBinding: contract.ResourceBinding{
		Kind: "recovery_record", Leaf: "recovery.json", Device: 1, Inode: 900,
		UID: 501, Mode: 0o600, LinkCount: 1,
	}}
}

func (value *MemoryJournal) Load() (RecoveryRecord, error) {
	if value.Record == nil {
		return RecoveryRecord{}, ErrNoRecoveryRecord
	}
	return cloneRecoveryRecord(*value.Record), nil
}

func (value *MemoryJournal) Save(record RecoveryRecord) error {
	value.SaveCount++
	if value.FailSaveAt > 0 && value.SaveCount == value.FailSaveAt {
		return errors.New("injected journal save failure")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	copy := cloneRecoveryRecord(record)
	value.Record = &copy
	value.History = append(value.History, cloneRecoveryRecord(record))
	return nil
}

func (value *MemoryJournal) Binding() (contract.ResourceBinding, error) {
	if value.Record == nil {
		return contract.ResourceBinding{}, ErrNoRecoveryRecord
	}
	return value.RecordBinding, nil
}

func (value *MemoryJournal) Remove(expected contract.ResourceBinding) error {
	value.RemoveCount++
	if value.FailRemove {
		return errors.New("injected journal remove failure")
	}
	if expected != value.RecordBinding {
		return errors.New("recovery record identity changed")
	}
	value.Record = nil
	return nil
}

func (value *MemoryJournal) Absent() (bool, error) {
	return value.Record == nil, nil
}

func cloneRecoveryRecord(source RecoveryRecord) RecoveryRecord {
	result := source
	result.Resources = append([]contract.ResourceBinding(nil), source.Resources...)
	if source.Supervisor != nil {
		supervisor := *source.Supervisor
		result.Supervisor = &supervisor
	}
	if source.Process != nil {
		process := *source.Process
		result.Process = &process
	}
	return result
}

type MemoryLocker struct {
	mu           sync.Mutex
	Held         bool
	Acquisitions int
	FailRelease  bool
}

func (value *MemoryLocker) Acquire(ctx context.Context) (func() error, error) {
	if value == nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("shadow attempt lock context is unavailable")
	}
	value.mu.Lock()
	if value.Held {
		value.mu.Unlock()
		return nil, errors.New("shadow attempt lock is already held")
	}
	value.Held = true
	value.Acquisitions++
	value.mu.Unlock()
	released := false
	return func() error {
		value.mu.Lock()
		defer value.mu.Unlock()
		if released || !value.Held {
			return errors.New("shadow attempt lock was already released")
		}
		released = true
		value.Held = false
		if value.FailRelease {
			return errors.New("injected shadow attempt lock release failure")
		}
		return nil
	}, nil
}
