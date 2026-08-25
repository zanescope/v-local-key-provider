//go:build !windows && !darwin

package daemon

import (
	"errors"
	"net"
)

func listen(config Config, _ string, _ string, _ bool) (net.Listener, string, string, func(), error) {
	if config.ReleaseBuild {
		return nil, "", "", func() {}, errors.New("release acquisition daemon transport is unsupported on this platform")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", func() {}, err
	}
	return listener, "tcp4-development", listener.Addr().String(), func() {}, nil
}

func verifyPeer(config Config, _ net.Conn, transport, clientPath string) (string, error) {
	if config.ReleaseBuild || transport != "tcp4-development" {
		return "", errors.New("daemon peer verification is unavailable on this platform")
	}
	path, err := config.ValidateClientPath(clientPath)
	if err != nil {
		return "", err
	}
	return "development:" + path, nil
}
