package main

import (
	"encoding/json"
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

// v1 保持历史行为：不带 deadline_ms，且不接受该字段。
func TestDecodeRequestV1RejectsDeadline(t *testing.T) {
	_, err := decodeRequest(strings.NewReader(
		`{"protocol":"v-local-key-provider/v1","request_id":"1","action":"acquire",` +
			`"account_dir":"a","db_dir":"b","scopes":["database"],"deadline_ms":1000}`))
	if err == nil {
		t.Fatal("v1 不应接受 deadline_ms")
	}
}

func TestDecodeRequestV2RequiresDeadline(t *testing.T) {
	_, err := decodeRequest(strings.NewReader(
		`{"protocol":"v-local-key-provider/v2","request_id":"1","action":"acquire",` +
			`"account_dir":"a","db_dir":"b","scopes":["database"]}`))
	if err == nil {
		t.Fatal("v2 缺少 deadline_ms 时应报错")
	}
}

func TestDecodeRequestV2RejectsOutOfRangeDeadline(t *testing.T) {
	for _, value := range []string{"0", "-1", "3600001"} {
		_, err := decodeRequest(strings.NewReader(
			`{"protocol":"v-local-key-provider/v2","request_id":"1","action":"acquire",` +
				`"account_dir":"a","db_dir":"b","scopes":["database"],"deadline_ms":` + value + `}`))
		if err == nil {
			t.Errorf("deadline_ms=%s 超出范围却被接受", value)
		}
	}
}

func TestDecodeRequestV2AcceptsDeadline(t *testing.T) {
	request, err := decodeRequest(strings.NewReader(
		`{"protocol":"v-local-key-provider/v2","request_id":"1","action":"acquire",` +
			`"account_dir":"a","db_dir":"b","scopes":["database"],"deadline_ms":75000}`))
	if err != nil {
		t.Fatal(err)
	}
	if request.DeadlineMS == nil || *request.DeadlineMS != 75000 {
		t.Fatalf("deadline_ms 未保留：%+v", request.DeadlineMS)
	}
}

// v2 请求要转成有限时限；v1 请求保持无限，行为与历史一致。
func TestOptionsCarryBudgetOnlyForV2(t *testing.T) {
	root := t.TempDir()
	account := filepath.Join(root, "account")
	db := filepath.Join(account, "db_storage")
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	deadline := int64(50)

	v2, err := optionsFromRequest(acquireRequest{
		AccountDir: account, DBDir: db, Scopes: []string{"database"}, DeadlineMS: &deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v2.budget.unlimited {
		t.Fatal("v2 请求的时限不应是无限")
	}
	time.Sleep(80 * time.Millisecond)
	if !v2.budget.expired() {
		t.Fatal("50 毫秒时限在 80 毫秒后仍未过期")
	}

	v1, err := optionsFromRequest(acquireRequest{
		AccountDir: account, DBDir: db, Scopes: []string{"database"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !v1.budget.unlimited || v1.budget.expired() {
		t.Fatal("v1 请求应保持无限时限")
	}
}

// 响应必须回显请求使用的协议版本，调用方据此校验。
func TestResponseEchoesRequestedProtocolVersion(t *testing.T) {
	for _, name := range []string{protocolName, protocolNameV2} {
		payload := map[string]any{
			"protocol": name, "request_id": "abc", "action": "acquire",
			"account_dir": "a", "db_dir": "b", "scopes": []string{"database"},
		}
		if name == protocolNameV2 {
			payload["deadline_ms"] = 1000
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request, err := decodeRequest(strings.NewReader(string(encoded)))
		if err != nil {
			t.Fatalf("%s 请求被拒：%v", name, err)
		}
		if request.Protocol != name {
			t.Fatalf("协议版本未保留：%q", request.Protocol)
		}
	}
}
