package provider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBudgetExpiry(t *testing.T) {
	if unlimitedBudget().expired() {
		t.Fatal("无限时限不应过期")
	}
	past := newBudget(time.Now().Add(-time.Second), 100)
	if !past.expired() {
		t.Fatal("已越过截止时刻的时限应判定为过期")
	}
	future := newBudget(time.Now(), 60_000)
	if future.expired() {
		t.Fatal("尚未到期的时限被误判为过期")
	}
}

func TestBudgetCanBeCappedForIndependentPhase(t *testing.T) {
	overall := newBudget(time.Now(), 60_000)
	phase := overall.cappedFor(10 * time.Millisecond)
	phaseDeadline, phaseBounded := phase.deadline()
	overallDeadline, overallBounded := overall.deadline()
	if !phaseBounded || !overallBounded || !phaseDeadline.Before(overallDeadline) {
		t.Fatal("phase budget did not select the earlier independent deadline")
	}
}

func TestBudgetHonorsSessionCapAndCancellation(t *testing.T) {
	value := newBudget(time.Now(), 60_000).cappedAt(time.Now().Add(-time.Millisecond))
	if !value.expired() {
		t.Fatal("session hard deadline did not cap request budget")
	}
	ctx, cancel := context.WithCancel(context.Background())
	value = unlimitedBudget().withCancellation(ctx.Done())
	if value.expired() {
		t.Fatal("live cancellation context expired budget")
	}
	cancel()
	if !value.expired() {
		t.Fatal("cancelled request did not expire budget")
	}
}

func TestBudgetDerivedCancellationValuesDoNotAlias(t *testing.T) {
	seed := make(chan struct{})
	first := make(chan struct{})
	second := make(chan struct{})
	base := unlimitedBudget().withCancellation(seed)
	left := base.withCancellation(first)
	right := base.withCancellation(second)
	close(first)
	if !left.expired() {
		t.Fatal("first derived budget lost its cancellation through slice aliasing")
	}
	if right.expired() {
		t.Fatal("independent derived budget inherited a sibling cancellation")
	}
}

func TestDecodeRequestV1RequiresDeadline(t *testing.T) {
	_, err := decodeRequest(strings.NewReader(
		`{"protocol":"v-local-key-provider/v1","request_id":"1","action":"acquire",` +
			`"account_dir":"a","db_dir":"b","scopes":["database"],"workflow":{"operation":"finalize"}}`))
	if err == nil {
		t.Fatal("v1 缺少 deadline_ms 时应报错")
	}
}

func TestDecodeRequestV1RejectsOutOfRangeDeadline(t *testing.T) {
	for _, value := range []string{"0", "-1", "3600001"} {
		_, err := decodeRequest(strings.NewReader(
			`{"protocol":"v-local-key-provider/v1","request_id":"1","action":"acquire",` +
				`"account_dir":"a","db_dir":"b","scopes":["database"],"deadline_ms":` + value + `,"workflow":{"operation":"finalize"}}`))
		if err == nil {
			t.Errorf("deadline_ms=%s 超出范围却被接受", value)
		}
	}
}

func TestDecodeRequestV1AcceptsDeadline(t *testing.T) {
	request, err := decodeRequest(strings.NewReader(
		`{"protocol":"v-local-key-provider/v1","request_id":"1","action":"acquire",` +
			`"account_dir":"a","db_dir":"b","scopes":["database"],"deadline_ms":75000,"workflow":{"operation":"finalize"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if request.DeadlineMS != 75000 {
		t.Fatalf("deadline_ms 未保留：%+v", request.DeadlineMS)
	}
}

func TestDecodeRequestBindsSessionOperationsAndReceipts(t *testing.T) {
	base := `{"protocol":"v-local-key-provider/v1","request_id":"1","action":"acquire",` +
		`"account_dir":"a","db_dir":"b","scopes":["database"],"deadline_ms":1000,"workflow":`
	invalid := []string{
		`{"operation":"observe","session_id":"session"}}`,
		`{"operation":"finalize","session_id":"session"}}`,
		`{"operation":"prepare","action_receipt":{"action":"trigger_database","user_confirmed":true}}}`,
		`{"operation":"cancel","session_id":"session","action_receipt":{"action":"trigger_database","user_confirmed":true}}}`,
	}
	for _, workflow := range invalid {
		if _, err := decodeRequest(strings.NewReader(base + workflow)); err == nil {
			t.Fatalf("unbound or misplaced workflow receipt was accepted: %s", workflow)
		}
	}
	valid := base + `{"operation":"observe","session_id":"session","expected_catalog_id":"catalog",` +
		`"action_receipt":{"action":"trigger_database","user_confirmed":true,"process_instance_id":"process"}}}`
	if _, err := decodeRequest(strings.NewReader(valid)); err != nil {
		t.Fatalf("bound observe receipt was rejected: %v", err)
	}
}

func TestOptionsCarryV1Budget(t *testing.T) {
	root := t.TempDir()
	account := filepath.Join(root, "account")
	db := filepath.Join(account, "db_storage")
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	deadline := int64(50)

	v1, err := optionsFromRequest(acquireRequest{
		AccountDir: account, DBDir: db, Scopes: []string{"database"}, DeadlineMS: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v1.Budget.IsUnlimited() {
		t.Fatal("v1 请求的时限不应是无限")
	}
	time.Sleep(80 * time.Millisecond)
	if !v1.Budget.Expired() {
		t.Fatal("50 毫秒时限在 80 毫秒后仍未过期")
	}
}

func TestDecodeRequestRejectsUnreleasedProtocolV2(t *testing.T) {
	_, err := decodeRequest(strings.NewReader(
		`{"protocol":"v-local-key-provider/v2","request_id":"1","action":"acquire",` +
			`"account_dir":"a","db_dir":"b","scopes":["database"],"deadline_ms":1000,"workflow":{"operation":"finalize"}}`))
	if err == nil {
		t.Fatal("未发布的 v2 不应继续被接受")
	}
}
