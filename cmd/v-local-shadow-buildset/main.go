package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	shadowbuildset "github.com/zanescope/v-local-key-provider/internal/shadowbuildset"
)

type summary struct {
	Version        string `json:"version"`
	BuildSetDigest string `json:"build_set_digest"`
	RouteMode      string `json:"route_mode"`
	Artifacts      int    `json:"artifacts"`
	Frozen         bool   `json:"frozen"`
	Verified       bool   `json:"verified"`
}

func canonicalStagingRoot(path string) (string, error) {
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.New("build-set staging root is not canonical")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", errors.New("build-set staging root is not owner-only")
	}
	return path, nil
}

func publishManifest(root string, payload []byte) (committed bool, err error) {
	target := filepath.Join(root, shadowbuildset.ManifestLeaf)
	pending := target + ".pending"
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return false, errors.New("build-set manifest already exists")
	}
	file, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, errors.New("build-set pending manifest cannot be created")
	}
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(pending)
			_ = os.Remove(target)
		}
	}()
	if _, err := file.Write(payload); err != nil || file.Sync() != nil || file.Chmod(0o444) != nil || file.Close() != nil {
		return false, errors.New("build-set manifest cannot be synchronized")
	}
	if err := os.Rename(pending, target); err != nil {
		return false, errors.New("build-set manifest cannot be published")
	}
	directory, err := os.Open(root)
	if err != nil {
		return false, errors.New("build-set staging root cannot be opened")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return false, errors.New("build-set staging root cannot be synchronized")
	}
	committed = true
	return true, nil
}

func freezeRoot(root, routeMode string) (summary, error) {
	root, err := canonicalStagingRoot(root)
	if err != nil {
		return summary{}, err
	}
	artifacts, err := shadowbuildset.InspectArtifacts(root)
	if err != nil {
		return summary{}, err
	}
	manifest, err := shadowbuildset.Assemble(routeMode, artifacts)
	if err != nil {
		return summary{}, err
	}
	payload, expectedDigest, err := shadowbuildset.Canonical(manifest)
	if err != nil {
		return summary{}, err
	}
	committed, err := publishManifest(root, payload)
	if err != nil {
		return summary{}, err
	}
	if err := os.Chmod(root, 0o555); err != nil {
		if committed {
			_ = os.Remove(filepath.Join(root, shadowbuildset.ManifestLeaf))
		}
		return summary{}, errors.New("build-set root cannot be frozen")
	}
	verified, digest, err := shadowbuildset.Load(root)
	if err != nil || digest != expectedDigest || verified.RouteMode != routeMode {
		return summary{}, errors.New("frozen build-set failed immediate verification")
	}
	return summary{
		Version: shadowbuildset.Version, BuildSetDigest: digest, RouteMode: verified.RouteMode,
		Artifacts: len(verified.Artifacts), Frozen: true, Verified: true,
	}, nil
}

func verifyRoot(root string) (summary, error) {
	manifest, digest, err := shadowbuildset.Load(root)
	if err != nil {
		return summary{}, err
	}
	return summary{
		Version: shadowbuildset.Version, BuildSetDigest: digest, RouteMode: manifest.RouteMode,
		Artifacts: len(manifest.Artifacts), Frozen: true, Verified: true,
	}, nil
}

func run() error {
	mode := flag.String("mode", "", "freeze or verify")
	root := flag.String("root", "", "canonical build-set directory")
	routeMode := flag.String("route-mode", "", "synthetic_only or production_capable")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" || (*mode != "freeze" && *mode != "verify") ||
		(*mode == "freeze" && *routeMode == "") || (*mode == "verify" && *routeMode != "") {
		return errors.New("build-set arguments are invalid")
	}
	var result summary
	var err error
	if *mode == "freeze" {
		result, err = freezeRoot(*root, *routeMode)
	} else {
		result, err = verifyRoot(*root)
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
