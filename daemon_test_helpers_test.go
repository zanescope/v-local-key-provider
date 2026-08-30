package provider

import "io"

func runTestAcquisitionDaemon(reader io.Reader, writer io.Writer) error {
	service, err := acquisitionDaemonServiceWithStoreFactory(newInertAcquisitionSessionStore)
	if err != nil {
		return err
	}
	return service.RunStdio(reader, writer)
}

func serveTestAcquisitionDaemon(endpointPath string) error {
	service, err := acquisitionDaemonServiceWithStoreFactory(newInertAcquisitionSessionStore)
	if err != nil {
		return err
	}
	return service.Serve(endpointPath)
}

func serveTestAcquisitionDaemonForClient(endpointPath, clientPath string) error {
	service, err := acquisitionDaemonServiceWithStoreFactory(newInertAcquisitionSessionStore)
	if err != nil {
		return err
	}
	return service.ServeForClient(endpointPath, clientPath)
}
