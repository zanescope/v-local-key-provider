//go:build !windows && !darwin

package provider

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func listenAcquisitionDaemon(_ string, _ string, _ bool) (net.Listener, string, string, func(), error) {
	if releaseBuild() {
		return nil, "", "", func() {}, errors.New("release acquisition daemon transport is unsupported on this platform")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", func() {}, err
	}
	return listener, "tcp4-development", listener.Addr().String(), func() {}, nil
}

func validateAcquisitionClientPath(path string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil || strings.TrimSpace(path) == "" {
		return "", errors.New("daemon client path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("daemon client is not a regular file")
	}
	return resolved, nil
}

func verifyAcquisitionDaemonPeer(_ net.Conn, transport, clientPath string) (string, error) {
	if releaseBuild() || transport != "tcp4-development" {
		return "", errors.New("daemon peer verification is unavailable on this platform")
	}
	path, err := validateAcquisitionClientPath(clientPath)
	if err != nil {
		return "", err
	}
	return "development:" + path, nil
}
