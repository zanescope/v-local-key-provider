package protocol

import (
	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	providermodel "github.com/zanescope/v-local-key-provider/internal/credential"
	providercrypto "github.com/zanescope/v-local-key-provider/internal/crypto"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
)

// Response 是 v1 wire response。嵌套值均为持有相应 schema 的 package 所定义类型的 alias，
// 因此 command package 无法另行定义平行 JSON 契约。
type Response struct {
	Protocol           string                            `json:"protocol"`
	RequestID          string                            `json:"request_id"`
	CatalogID          string                            `json:"catalog_id,omitempty"`
	CatalogEntries     []catalogmodel.Database           `json:"catalog_entries,omitempty"`
	DatabaseKeys       map[string]string                 `json:"database_keys,omitempty"`
	DatabaseProfiles   map[string]string                 `json:"database_profiles,omitempty"`
	DatabaseCredential *providermodel.DatabaseCredential `json:"database_credential,omitempty"`
	ImageKeys          *ImageKeys                        `json:"image_keys,omitempty"`
	Profiles           []providercrypto.Summary          `json:"profiles,omitempty"`
	Diagnostics        diagnosticmodel.Diagnostics       `json:"diagnostics"`
}
