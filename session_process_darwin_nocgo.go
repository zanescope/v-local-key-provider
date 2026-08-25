//go:build darwin && !cgo

package provider

func platformProcessInstanceID() string {
	return "darwin:cgo-unavailable"
}
