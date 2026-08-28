//go:build windows || darwin

package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	livePrivateConfigSchema   = 1
	livePrivateConfigMaxBytes = 16 * 1024
)

type livePrivateConfig struct {
	SchemaVersion int
	AccountDir    string
	DBDir         string
}

func decodeLivePrivateConfig(payload []byte) (livePrivateConfig, error) {
	if len(payload) == 0 || len(payload) > livePrivateConfigMaxBytes {
		return livePrivateConfig{}, errors.New("live private config size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return livePrivateConfig{}, errors.New("live private config must be an object")
	}
	seen := map[string]bool{}
	var result livePrivateConfig
	for decoder.More() {
		nameToken, tokenErr := decoder.Token()
		name, ok := nameToken.(string)
		if tokenErr != nil || !ok || seen[name] {
			return livePrivateConfig{}, errors.New("live private config contains an invalid or duplicate field")
		}
		seen[name] = true
		switch name {
		case "schema_version":
			if err := decoder.Decode(&result.SchemaVersion); err != nil {
				return livePrivateConfig{}, errors.New("live private config schema is invalid")
			}
		case "account_dir":
			if err := decoder.Decode(&result.AccountDir); err != nil {
				return livePrivateConfig{}, errors.New("live private config account directory is invalid")
			}
		case "db_dir":
			if err := decoder.Decode(&result.DBDir); err != nil {
				return livePrivateConfig{}, errors.New("live private config database directory is invalid")
			}
		default:
			return livePrivateConfig{}, errors.New("live private config contains an unknown field")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return livePrivateConfig{}, errors.New("live private config object is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return livePrivateConfig{}, errors.New("live private config contains trailing data")
	}
	if len(seen) != 3 || result.SchemaVersion != livePrivateConfigSchema {
		return livePrivateConfig{}, errors.New("live private config schema is incomplete")
	}
	if err := validateLivePrivateDataDirectory(result.AccountDir); err != nil {
		return livePrivateConfig{}, errors.New("live private config account directory is unsafe")
	}
	if err := validateLivePrivateDataDirectory(result.DBDir); err != nil {
		return livePrivateConfig{}, errors.New("live private config database directory is unsafe")
	}
	return result, nil
}

func validateLivePrivateDataDirectory(path string) error {
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) ||
		strings.ContainsAny(path, "\x00\r\n") {
		return os.ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return os.ErrInvalid
	}
	return nil
}

func loadLivePrivateConfig(t *testing.T) livePrivateConfig {
	t.Helper()
	payload, err := readLivePrivateConfig()
	if err != nil {
		t.Fatal("runner-local live regression config is unavailable or unsafe")
	}
	config, err := decodeLivePrivateConfig(payload)
	for index := range payload {
		payload[index] = 0
	}
	if err != nil {
		t.Fatal("runner-local live regression config is invalid")
	}
	return config
}

func TestDecodeLivePrivateConfigRequiresExactSchemaAndDirectories(t *testing.T) {
	account := t.TempDir()
	database := t.TempDir()
	payload, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"account_dir":    account,
		"db_dir":         database,
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := decodeLivePrivateConfig(payload)
	if err != nil || config.AccountDir != account || config.DBDir != database {
		t.Fatalf("valid private config was rejected: %v", err)
	}

	for _, invalid := range [][]byte{
		bytes.Replace(payload, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1),
		append(bytes.TrimSuffix(payload, []byte("}")), []byte(`,"extra":true}`)...),
		[]byte(`{"schema_version":1,"schema_version":1,"account_dir":"x","db_dir":"y"}`),
		[]byte(`{"schema_version":1,"account_dir":"relative","db_dir":"relative"}`),
		append(payload, []byte(" trailing")...),
	} {
		if _, err := decodeLivePrivateConfig(invalid); err == nil {
			t.Fatal("non-exact or unsafe private config was accepted")
		}
	}
}
