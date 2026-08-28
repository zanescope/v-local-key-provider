//go:build !darwin

package provider

func delegateAcquisitionDaemonToPlatformHelper(endpointPath, clientPath string) (bool, error) {
	return false, nil
}
