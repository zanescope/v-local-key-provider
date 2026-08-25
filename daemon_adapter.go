package provider

import (
	"io"

	daemonmodel "github.com/zanescope/v-local-key-provider/internal/daemon"
)

const acquisitionDaemonSchemaVersion = daemonmodel.SchemaVersion

type acquisitionDaemonEndpoint = daemonmodel.Endpoint
type acquisitionDaemonRequest = daemonmodel.Request
type acquisitionDaemonError = daemonmodel.Error
type acquisitionDaemonResponse = daemonmodel.Response

func acquisitionDaemonService() (*daemonmodel.Service, error) {
	return daemonmodel.New(daemonmodel.Config{
		Version:            version,
		ReleaseBuild:       releaseBuild(),
		RuntimeContext:     acquisitionDaemonRuntimeContext,
		ValidateClientPath: validateAcquisitionClientPath,
		IsLinkOrReparse:    pathIsLinkOrReparse,
		SamePath:           sameCanonicalPath,
		MarkSensitive:      markSensitiveBytes,
		ZeroSensitive:      zeroBytes,
		NewBackend: func(context daemonmodel.BackendContext) daemonmodel.Backend {
			store := newAcquisitionSessionStore()
			store.helperMode = context.HelperMode
			store.helperStatus = context.HelperStatus
			return daemonmodel.Backend{
				HandleContext: store.handleContext,
				CancelSession: store.cancelSession,
				ActiveCount:   store.activeCount,
				Close:         store.closeAll,
			}
		},
	})
}

func runAcquisitionDaemon(reader io.Reader, writer io.Writer) error {
	service, err := acquisitionDaemonService()
	if err != nil {
		return err
	}
	return service.RunStdio(reader, writer)
}

func serveAcquisitionDaemon(endpointPath string) error {
	service, err := acquisitionDaemonService()
	if err != nil {
		return err
	}
	return service.Serve(endpointPath)
}

func serveAcquisitionDaemonForClient(endpointPath, clientPath string) error {
	service, err := acquisitionDaemonService()
	if err != nil {
		return err
	}
	return service.ServeForClient(endpointPath, clientPath)
}

func serveAcquisitionDaemonAs(endpointPath, advertisedProviderPath, clientPath string, developmentTCP bool) error {
	service, err := acquisitionDaemonService()
	if err != nil {
		return err
	}
	return service.ServeAs(endpointPath, advertisedProviderPath, clientPath, developmentTCP)
}

func acquisitionDaemonHelperContext(advertisedProviderPath string) (bool, string) {
	context := daemonmodel.ContextForProvider(advertisedProviderPath)
	return context.HelperMode, context.HelperStatus
}

func validateAcquisitionDaemonProviderVersion(advertised string) error {
	return daemonmodel.ValidateProviderVersion(advertised, version)
}

func randomDaemonToken() (string, error) {
	return daemonmodel.RandomToken(zeroBytes)
}
