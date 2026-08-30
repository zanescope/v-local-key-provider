//go:build darwin

// Package shadowproduction loads the immutable, production-capable artifacts
// used by the pre-launch Shadow stages. Runtime promotion is a separate gate.
package shadowproduction

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	shadowbuildset "github.com/zanescope/v-local-key-provider/internal/shadowbuildset"
	contract "github.com/zanescope/v-local-key-provider/internal/shadowcontract"
	shadowsource "github.com/zanescope/v-local-key-provider/internal/shadowsource"
	shadowtransform "github.com/zanescope/v-local-key-provider/internal/shadowtransform"
)

type Bundle struct {
	Root           string
	BuildSet       shadowbuildset.Manifest
	Digest         string
	Source         shadowsource.Manifest
	Transformation shadowtransform.Manifest
}

func artifactForRole(manifest shadowbuildset.Manifest, role string) (shadowbuildset.Artifact, bool) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Role == role {
			return artifact, true
		}
	}
	return shadowbuildset.Artifact{}, false
}

func LoadBundle(root string) (Bundle, error) {
	manifest, digest, err := shadowbuildset.Load(root)
	if err != nil || manifest.RouteMode != shadowbuildset.RouteProductionCapable {
		return Bundle{}, errors.New("production build set is unavailable or not production-capable")
	}
	sourcePayload, err := shadowbuildset.LoadArtifact(root, digest, "source_manifest")
	if err != nil {
		return Bundle{}, err
	}
	transformationPayload, err := shadowbuildset.LoadArtifact(root, digest, "transformation_manifest")
	if err != nil {
		return Bundle{}, err
	}
	var source shadowsource.Manifest
	var transformation shadowtransform.Manifest
	if shadowbuildset.DecodeStrict(sourcePayload, &source) != nil || source.Validate() != nil ||
		shadowbuildset.DecodeStrict(transformationPayload, &transformation) != nil || transformation.Validate() != nil {
		return Bundle{}, errors.New("production build set contains an invalid frozen manifest")
	}
	_, sourceDigest, sourceErr := shadowsource.CanonicalManifest(source)
	_, transformationDigest, transformationErr := shadowtransform.CanonicalManifest(transformation)
	if sourceErr != nil || transformationErr != nil || sourceDigest != manifest.SourceManifestDigest ||
		transformationDigest != manifest.TransformationManifestDigest ||
		source.TransformationManifestDigest != transformationDigest ||
		source.SourceVersion != transformation.SourceVersion || source.SourceBuild != transformation.SourceBuild ||
		source.InventoryDigest != transformation.SourceInventoryDigest {
		return Bundle{}, errors.New("production build-set manifests are not cross-bound")
	}
	allowedEntitlements := map[string]bool{}
	for _, artifact := range manifest.Artifacts {
		if strings.HasPrefix(artifact.Role, "entitlement_profile:") {
			allowedEntitlements[artifact.Leaf] = true
		}
	}
	for _, object := range transformation.SigningOrder {
		if !allowedEntitlements[object.EntitlementsLeaf] {
			return Bundle{}, errors.New("production signing plan references an artifact outside the build set")
		}
	}
	return Bundle{
		Root: filepath.Clean(root), BuildSet: manifest, Digest: digest,
		Source: source, Transformation: transformation,
	}, nil
}

func (value Bundle) SupervisorBinding() (contract.ResourceBinding, error) {
	artifact, found := artifactForRole(value.BuildSet, "supervisor")
	if !found || value.Root == "" || value.Digest == "" {
		return contract.ResourceBinding{}, errors.New("production supervisor artifact is unavailable")
	}
	path := filepath.Join(value.Root, artifact.Leaf)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		uint32(info.Mode().Perm()) != artifact.Mode || info.Size() != artifact.Size {
		return contract.ResourceBinding{}, errors.New("production supervisor artifact identity drifted")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return contract.ResourceBinding{}, errors.New("production supervisor artifact identity is unavailable")
	}
	binding := contract.ResourceBinding{
		Kind: "supervisor", Leaf: artifact.Leaf, Device: uint64(stat.Dev), Inode: uint64(stat.Ino),
		UID: stat.Uid, Mode: uint32(info.Mode().Perm()), LinkCount: uint64(stat.Nlink), DigestSHA256: artifact.SHA256,
	}
	if err := binding.Validate(); err != nil {
		return contract.ResourceBinding{}, err
	}
	return binding, nil
}
