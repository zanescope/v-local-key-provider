package provider

import (
	"net"
	"time"
)

type deadlineListener interface {
	SetDeadline(time.Time) error
}

func setAcquisitionDaemonListenerDeadline(listener net.Listener, deadline time.Time) {
	if value, ok := listener.(deadlineListener); ok {
		_ = value.SetDeadline(deadline)
	}
}
