// Package acquisition owns target discovery, candidate collection, and
// cryptographic validation. Platform code supplies OS policy and process
// observations through the narrow interfaces in this package.
package acquisition

import (
	catalogmodel "github.com/zanescope/v-local-key-provider/internal/catalog"
	diagnosticmodel "github.com/zanescope/v-local-key-provider/internal/diagnostics"
	platformmodel "github.com/zanescope/v-local-key-provider/internal/platform"
	protocolmodel "github.com/zanescope/v-local-key-provider/internal/protocol"
	"github.com/zanescope/v-local-key-provider/internal/workbudget"
)

type DatabasePage = catalogmodel.Page

// Targets is the discovery result consumed as read-only input by platform collectors.
type Targets struct {
	BySalt  map[string][]string
	Pages   []DatabasePage
	Count   int
	Catalog catalogmodel.Catalog
}

// MediaEvidence contains bounded samples used to validate media-key candidates.
type MediaEvidence struct {
	V2Blocks      [][16]byte
	XORCandidates map[byte]int
}

// PlatformRequest contains only the acquisition inputs an OS driver needs.
// Catalog-key handling and final response assembly remain at the command edge.
type PlatformRequest struct {
	AccountDir      string
	DBDir           string
	Database        bool
	Media           bool
	Budget          workbudget.Budget
	HelperMode      bool
	HelperStatus    string
	PlatformSession PlatformSession
	ActionReceipt   string
}

// PlatformSession is a bounded, synchronized source of long-lived platform
// observations. Implementations must make Close idempotent.
type PlatformSession interface {
	Collect(*Collector) platformmodel.HookSnapshot
	Status() platformmodel.HookSnapshot
	Close()
}

// PlatformDriver is the command-to-OS acquisition seam. It deliberately uses
// only internal domain models, so no internal package needs to import main.
type PlatformDriver interface {
	Acquire(Targets, MediaEvidence, PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error)
}

type PlatformDriverFunc func(Targets, MediaEvidence, PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error)

func (driver PlatformDriverFunc) Acquire(targets Targets, media MediaEvidence, request PlatformRequest) (protocolmodel.Response, diagnosticmodel.Diagnostics, error) {
	return driver(targets, media, request)
}

// Private aliases keep the implementation and its package-local tests concise.
type databaseTargets = Targets
type databasePage = DatabasePage
type mediaEvidence = MediaEvidence
type imageKeys = protocolmodel.ImageKeys
type diagnostics = diagnosticmodel.Diagnostics
type databaseCatalog = catalogmodel.Catalog
type catalogDatabase = catalogmodel.Database
type budget = workbudget.Budget

func unlimitedBudget() budget { return workbudget.Unlimited() }
