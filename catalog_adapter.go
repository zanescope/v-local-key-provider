package provider

import (
	"os"

	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
)

type databaseClassification = catalogmodel.Classification
type catalogDatabase = catalogmodel.Database
type databaseCatalog = catalogmodel.Catalog

const (
	classificationEncrypted  = catalogmodel.ClassificationEncrypted
	classificationPlaintext  = catalogmodel.ClassificationPlaintext
	classificationUnreadable = catalogmodel.ClassificationUnreadable
	classificationUnstable   = catalogmodel.ClassificationUnstable
	classificationTruncated  = catalogmodel.ClassificationTruncated
	maxCatalogDatabaseFiles  = catalogmodel.MaxDatabaseFiles
)

func randomCatalogKey() ([]byte, error) {
	return catalogmodel.RandomKey()
}

func catalogHMAC(key []byte, values ...string) string {
	return catalogmodel.HMAC(key, values...)
}

func safeRelativePath(root, path string) (string, error) {
	return catalogmodel.SafeRelativePath(root, path)
}

func canonicalFileID(file *os.File) (string, error) {
	return catalogmodel.CanonicalFileID(file, platformFileIdentity)
}

func catalogID(key []byte, databases []catalogDatabase, discoveryErrors []string) string {
	return catalogmodel.ID(key, databases, discoveryErrors)
}

func discoverDatabaseCatalog(dbDir string, remaining budget, key []byte) (databaseCatalog, []databasePage, error) {
	result, pages, err := catalogmodel.Discover(dbDir, key, catalogmodel.PlatformPolicy{
		FileIdentity:       platformFileIdentity,
		IsLinkOrReparse:    pathIsLinkOrReparse,
		CanonicalPathKey:   catalogPathKey,
		AcquisitionExpired: remaining.expired,
	})
	if err != nil {
		return databaseCatalog{}, nil, err
	}
	return result, pages, nil
}
