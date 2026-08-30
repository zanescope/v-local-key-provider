package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	shadowsource "github.com/zanescope/v-local-key-provider/internal/shadowsource"
	shadowtransform "github.com/zanescope/v-local-key-provider/internal/shadowtransform"
)

const (
	maxInputBytes              = int64(1024 * 1024)
	sourceManifestLeaf         = "shadow-source-manifest-v1.json"
	transformationManifestLeaf = "shadow-transformation-manifest-v1.json"
)

type freezeSummary struct {
	Version                      string `json:"version"`
	SourceVersion                string `json:"source_version"`
	SourceBuild                  string `json:"source_build"`
	SourceInventoryDigest        string `json:"source_inventory_digest"`
	SourceManifestDigest         string `json:"source_manifest_digest"`
	TransformationManifestDigest string `json:"transformation_manifest_digest"`
	RewriteInputs                int    `json:"rewrite_inputs"`
	SigningObjects               int    `json:"signing_objects"`
	EntitlementProfiles          int    `json:"entitlement_profiles"`
	Frozen                       bool   `json:"frozen"`
}

type frozenFile struct {
	leaf    string
	payload []byte
}

func readJSON(path string, destination any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 1 || info.Size() > maxInputBytes {
		return errors.New("manifest-freezer input file is invalid")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return errors.New("manifest-freezer input file is unreadable")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("manifest-freezer input JSON is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("manifest-freezer input JSON has trailing data")
	}
	return nil
}

func canonicalOutputRoot(path string) (string, error) {
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.New("manifest-freezer output root is not canonical")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", errors.New("manifest-freezer output root is not an owner-only staging directory")
	}
	return path, nil
}

func writeOne(root string, value frozenFile) (string, error) {
	if filepath.Base(value.leaf) != value.leaf || len(value.payload) == 0 || len(value.payload) > int(maxInputBytes) {
		return "", errors.New("manifest-freezer output is invalid")
	}
	target := filepath.Join(root, value.leaf)
	pending := target + ".pending"
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return "", errors.New("manifest-freezer refuses to overwrite an output")
	}
	file, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.New("manifest-freezer pending output cannot be created")
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(pending)
		}
	}()
	if _, err := file.Write(value.payload); err != nil || file.Sync() != nil || file.Chmod(0o444) != nil || file.Close() != nil {
		return "", errors.New("manifest-freezer output cannot be committed")
	}
	if err := os.Rename(pending, target); err != nil {
		return "", errors.New("manifest-freezer output cannot be published")
	}
	keep = true
	return target, nil
}

func writeFrozenFiles(root string, values []frozenFile) (err error) {
	root, err = canonicalOutputRoot(root)
	if err != nil {
		return err
	}
	values = append([]frozenFile(nil), values...)
	sort.Slice(values, func(left, right int) bool { return values[left].leaf < values[right].leaf })
	for index := range values {
		if index > 0 && values[index-1].leaf == values[index].leaf {
			return errors.New("manifest-freezer output leaf is duplicated")
		}
	}
	created := []string{}
	defer func() {
		if err == nil {
			return
		}
		for index := len(created) - 1; index >= 0; index-- {
			_ = os.Remove(created[index])
		}
	}()
	for _, value := range values {
		path, writeErr := writeOne(root, value)
		if writeErr != nil {
			return writeErr
		}
		created = append(created, path)
	}
	directory, err := os.Open(root)
	if err != nil {
		return errors.New("manifest-freezer output root cannot be synchronized")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("manifest-freezer output root cannot be synchronized")
	}
	return nil
}

func freeze(ctx context.Context, source string, references []shadowsource.RewriteReference) (freezeSummary, []frozenFile, error) {
	snapshot, err := (shadowsource.Inspector{}).Inspect(ctx, source, references)
	if err != nil {
		return freezeSummary{}, nil, err
	}
	rewrites := make([]shadowtransform.PlistRewrite, len(snapshot.RewriteInputs))
	for index, input := range snapshot.RewriteInputs {
		rewrites[index] = shadowtransform.PlistRewrite{Path: input.Path, Key: input.Key, Expected: input.Expected}
	}
	discovery, err := shadowtransform.Discover(ctx, source, shadowtransform.DiscoveryInput{
		SourceVersion: snapshot.SourceVersion, SourceBuild: snapshot.SourceBuild,
		SourceInventoryDigest: snapshot.InventoryDigest, RewriteInputs: rewrites,
	})
	if err != nil {
		return freezeSummary{}, nil, err
	}
	transformationPayload, transformationDigest, err := shadowtransform.CanonicalManifest(discovery.Manifest)
	if err != nil {
		return freezeSummary{}, nil, err
	}
	sourceManifest, err := shadowsource.Freeze(snapshot, transformationDigest)
	if err != nil {
		return freezeSummary{}, nil, err
	}
	sourcePayload, sourceDigest, err := shadowsource.CanonicalManifest(sourceManifest)
	if err != nil {
		return freezeSummary{}, nil, err
	}
	files := []frozenFile{
		{leaf: sourceManifestLeaf, payload: sourcePayload},
		{leaf: transformationManifestLeaf, payload: transformationPayload},
	}
	for _, profile := range discovery.Profiles {
		files = append(files, frozenFile{leaf: profile.Leaf, payload: profile.Payload})
	}
	return freezeSummary{
		Version: "v-local-shadow-manifest-freeze/v1", SourceVersion: snapshot.SourceVersion,
		SourceBuild: snapshot.SourceBuild, SourceInventoryDigest: snapshot.InventoryDigest,
		SourceManifestDigest: sourceDigest, TransformationManifestDigest: transformationDigest,
		RewriteInputs: len(snapshot.RewriteInputs), SigningObjects: len(discovery.Manifest.SigningOrder),
		EntitlementProfiles: len(discovery.Profiles),
	}, files, nil
}

func run() error {
	mode := flag.String("mode", "", "inspect or freeze")
	source := flag.String("source", "/Applications/WeChat.app", "canonical source App path")
	referencesPath := flag.String("references", "", "rewrite-reference JSON path")
	outputRoot := flag.String("output-dir", "", "owner-only build staging directory")
	flag.Parse()
	if flag.NArg() != 0 || *referencesPath == "" || (*mode != "inspect" && *mode != "freeze") ||
		(*mode == "inspect" && *outputRoot != "") || (*mode == "freeze" && *outputRoot == "") {
		return errors.New("manifest-freezer arguments are invalid")
	}
	var references []shadowsource.RewriteReference
	if err := readJSON(*referencesPath, &references); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	summary, files, err := freeze(ctx, *source, references)
	if err != nil {
		return err
	}
	if *mode == "freeze" {
		if err := writeFrozenFiles(*outputRoot, files); err != nil {
			return err
		}
		summary.Frozen = true
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(summary)
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
