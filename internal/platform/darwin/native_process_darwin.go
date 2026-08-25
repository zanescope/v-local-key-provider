//go:build darwin && cgo

package darwin

func (driver *nativeDriver) ListProcesses() ([]Process, string, error) {
	uid := 0
	if driver.runtime.UID != nil {
		uid = driver.runtime.UID()
	}
	return DiscoverProcesses(driver.runtime.RunOutput, driver.clear, uid)
}
