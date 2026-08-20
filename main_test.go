package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDecodeRequest(t *testing.T) {
	payload, err := json.Marshal(acquireRequest{
		Protocol:   protocolName,
		RequestID:  "request-1",
		Action:     "acquire",
		AccountDir: "account",
		DBDir:      "db",
		Scopes:     []string{"database", "image"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := decodeRequest(strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if request.Protocol != protocolName || request.RequestID != "request-1" {
		t.Fatalf("请求字段未保留：%+v", request)
	}
}

func TestDecodeRequestRejectsUnknownFields(t *testing.T) {
	_, err := decodeRequest(strings.NewReader(`{"protocol":"v-local-key-provider/v1","request_id":"1","action":"acquire","account_dir":"a","db_dir":"b","scopes":["database"],"secret":"x"}`))
	if err == nil {
		t.Fatal("包含未知字段的请求不应通过")
	}
}

func TestOptionsFromRequest(t *testing.T) {
	root := t.TempDir()
	account := filepath.Join(root, "account")
	db := filepath.Join(account, "db_storage")
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	options, err := optionsFromRequest(acquireRequest{
		AccountDir: account,
		DBDir:      db,
		Scopes:     []string{"database", "image"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.database || !options.media {
		t.Fatalf("scope 未正确解析：%+v", options)
	}
}

func TestVersionHasDevelopmentDefault(t *testing.T) {
	if version == "" {
		t.Fatal("版本号不能为空")
	}
}

func TestRunAcquireReturnsDeadlineDiagnosticsAfterDiscoveryBudget(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("platform acquisition is unsupported")
	}
	root := t.TempDir()
	account := filepath.Join(root, "account")
	db := filepath.Join(root, "db")
	if err := os.MkdirAll(account, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := runAcquire(acquireOptions{
		accountDir: account, dbDir: db, database: true,
		budget: newBudget(time.Now().Add(-time.Second), 1),
	})
	if err != nil {
		t.Fatalf("expired discovery should return diagnostics, got error: %v", err)
	}
	if !result.Diagnostics.BudgetExhausted || result.Diagnostics.ProcessAccessStatus != "deadline_exhausted" {
		t.Fatalf("expired discovery diagnostics missing: %+v", result.Diagnostics)
	}
}
