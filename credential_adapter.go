package provider

import credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"

type databaseCredential = credentialmodel.DatabaseCredential
type credentialRoot = credentialmodel.Root
type credentialOverride = credentialmodel.Override

func randomOpaqueID() (string, error) {
	return credentialmodel.RandomOpaqueID()
}
