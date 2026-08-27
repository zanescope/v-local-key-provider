package provider

import credentialmodel "github.com/zanescope/v-local-key-provider/internal/credential"

type databaseCredential = credentialmodel.DatabaseCredential
type credentialOverride = credentialmodel.Override

func randomOpaqueID() (string, error) {
	return credentialmodel.RandomOpaqueID()
}
