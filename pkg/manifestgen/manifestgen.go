package manifestgen

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/osbuild/blueprint/pkg/blueprint"
	"github.com/osbuild/image-builder/internal/common"
	"github.com/osbuild/image-builder/pkg/arch"
	"github.com/osbuild/image-builder/pkg/container"
	"github.com/osbuild/image-builder/pkg/depsolvednf"
	"github.com/osbuild/image-builder/pkg/distro"
	"github.com/osbuild/image-builder/pkg/flatpak"
	"github.com/osbuild/image-builder/pkg/manifest"
	"github.com/osbuild/image-builder/pkg/osbuild"
	"github.com/osbuild/image-builder/pkg/ostree"
	"github.com/osbuild/image-builder/pkg/reporegistry"
	"github.com/osbuild/image-builder/pkg/rpmlist"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/osbuild/image-builder/pkg/sbom"
)

const (
	defaultDepsolveCacheDir = "osbuild-depsolve-dnf"
)

var (
	ErrContainerArchMismatch = errors.New("requested container architecture does not match resolved container")
)

// Options contains the optional settings for the manifest generation.
// For unset values defaults will be used.
type Options struct {
	// Cachedir specified the rpmmd cache directory (rpm metadata)
	// If unset a default based on the xdgCacheHome is used
	// (e.g. /root/.cache/osbuild-store)
	Cachedir string

	// RpmDownloader allows to switch between the librepo and
	// libcurl download backends.
	RpmDownloader osbuild.RpmDownloader

	// WarningsOutput will receive any warnings that are part of
	// the manifest generation. If it is unset any warnings will
	// generate an error.
	WarningsOutput io.Writer

	// DepsolveWarningsOutput will receive any warnings that are
	// part of the depsolving step. If it is unset output ends up
	// on the default stdout/stderr.
	DepsolveWarningsOutput io.Writer

	// CustomSeed overrides the default rng seed, this is mostly
	// useful for testing
	CustomSeed *int64

	// OverrideRepos overrides the default repository selection.
	// This is mostly useful for testing
	OverrideRepos []rpmmd.RepoConfig

	// Custom "solver" functions, if unset the defaults will be
	// used. Only needed for specialized use-cases.
	Depsolve          DepsolveFunc
	ContainerResolver ContainerResolverFunc
	CommitResolver    CommitResolverFunc
	FlatpakResolver   FlatpakResolverFunc

	// Use the a bootstrap container to buildroot (useful for e.g.
	// cross-arch or cross-distro builds)
	UseBootstrapContainer bool

	RPMListWriter RPMListWriterFunc
}

// Generator can generate an osbuild manifest from a given repository
// and options.
type Generator struct {
	cacheDir string

	depsolve               DepsolveFunc
	containerResolver      ContainerResolverFunc
	commitResolver         CommitResolverFunc
	flatpakResolver        FlatpakResolverFunc
	warningsOutput         io.Writer
	depsolveWarningsOutput io.Writer

	reporegistry *reporegistry.RepoRegistry

	rpmDownloader osbuild.RpmDownloader

	customSeed    *int64
	overrideRepos []rpmmd.RepoConfig

	useBootstrapContainer bool
	rpmlistWriter         RPMListWriterFunc
}

// New will create a new manifest generator
func New(reporegistry *reporegistry.RepoRegistry, opts *Options) (*Generator, error) {
	if opts == nil {
		opts = &Options{}
	}
	mg := &Generator{
		reporegistry: reporegistry,

		cacheDir:               opts.Cachedir,
		depsolve:               opts.Depsolve,
		containerResolver:      opts.ContainerResolver,
		commitResolver:         opts.CommitResolver,
		rpmDownloader:          opts.RpmDownloader,
		warningsOutput:         opts.WarningsOutput,
		depsolveWarningsOutput: opts.DepsolveWarningsOutput,
		customSeed:             opts.CustomSeed,
		overrideRepos:          opts.OverrideRepos,
		useBootstrapContainer:  opts.UseBootstrapContainer,
		rpmlistWriter:          opts.RPMListWriter,
	}
	if mg.depsolve == nil {
		mg.depsolve = DefaultDepsolve
	}
	if mg.containerResolver == nil {
		mg.containerResolver = func(containerSources map[string][]container.SourceSpec, archName string) (map[string][]container.Spec, error) {
			return container.NewBlockingResolver(archName).ResolveAll(containerSources)
		}
	}
	if mg.commitResolver == nil {
		mg.commitResolver = ostree.ResolveAll
	}
	if mg.flatpakResolver == nil {
		mg.flatpakResolver = flatpak.ResolveAll
	}
	if mg.cacheDir == "" {
		xdgCacheHomeDir, err := xdgCacheHome()
		if err != nil {
			return nil, err
		}
		mg.cacheDir = filepath.Join(xdgCacheHomeDir, defaultDepsolveCacheDir)
	}

	return mg, nil
}

// Result is a generated manifest and its depsolved payload RPM inventory.
type Result struct {
	// Manifest is the serialized osbuild manifest.
	Manifest []byte

	// Packages is the union of depsolved RPMs from payload pipelines (including
	// extras), excluding buildroot tooling. It is not a full image inventory:
	// packages inside OSTree commits, bootc images, and containers are not inspected.
	// Only SBOM fields are retained, never repository or download credentials.
	Packages []sbom.Package
}

// Generate will generate a new manifest for the given distro/imageType/arch
// combination.
func (mg *Generator) Generate(bp *blueprint.Blueprint, imgType distro.ImageType, imgOpts *distro.ImageOptions) (Result, error) {
	if imgOpts == nil {
		imgOpts = &distro.ImageOptions{}
	}
	imgOpts.UseBootstrapContainer = mg.useBootstrapContainer
	a := imgType.Arch()
	dist := a.Distro()

	var repos []rpmmd.RepoConfig
	if mg.overrideRepos != nil {
		repos = mg.overrideRepos
	} else {
		var err error
		repos, err = mg.reporegistry.ReposByImageTypeName(dist.Name(), a.Name(), imgType.Name())
		if err != nil {
			return Result{}, err
		}
	}
	// To support "user" a.k.a. "3rd party" repositories, these
	// will have to be added to the repos with
	// <repo_item>.PackageSets set to the "payload" pipeline names
	// for the given image type, see e.g. distro/rhel/imagetype.go:Manifest()
	preManifest, warnings, err := imgType.Manifest(bp, *imgOpts, repos, mg.customSeed)
	if err != nil {
		return Result{}, err
	}
	if len(warnings) > 0 {
		warn := strings.Join(warnings, "\n")
		if mg.warningsOutput != nil {
			fmt.Fprint(mg.warningsOutput, warn)
		} else {
			return Result{}, fmt.Errorf("Warnings during manifest creation:\n%v", warn)
		}
	}
	pkgSetChains, err := preManifest.GetPackageSetChains()
	if err != nil {
		return Result{}, err
	}
	solver := depsolvednf.NewSolver(dist.ModulePlatformID(), dist.Releasever(), a.Name(), dist.Name(), mg.cacheDir)
	if dd, ok := dist.(distro.CustomDepsolverDistro); ok {
		// XXX: it would be nice to have access to arch.Arch
		// from distro.Arch but we dont so we have to do without.
		archi := common.Must(arch.FromString(a.Name()))
		customSolver, cleanupFunc, err := dd.Depsolver(mg.cacheDir, archi)
		if err != nil {
			return Result{}, err
		}
		if customSolver != nil {
			solver = customSolver
		}
		defer func() {
			if err := cleanupFunc(); err != nil {
				fmt.Fprintf(mg.warningsOutput, "WARNING: cleanup failed: %v\n", err)
			}
		}()
	}
	depsolved, err := mg.depsolve(solver, mg.cacheDir, mg.depsolveWarningsOutput, pkgSetChains, dist, a.Name())
	if err != nil {
		return Result{}, err
	}
	containerSpecs, err := mg.containerResolver(preManifest.GetContainerSourceSpecs(), a.Name())
	if err != nil {
		return Result{}, err
	}
	for _, specs := range containerSpecs {
		for _, spec := range specs {
			if spec.Arch.String() != a.Name() {
				return Result{}, fmt.Errorf("%w: %q != %q", ErrContainerArchMismatch, spec.Arch, a.Name())
			}
		}
	}

	commitSpecs, err := mg.commitResolver(preManifest.GetOSTreeSourceSpecs())
	if err != nil {
		return Result{}, err
	}

	flatpakSpecs, err := mg.flatpakResolver(preManifest.GetFlatpakSourceSpecs())
	if err != nil {
		return Result{}, err
	}

	opts := &manifest.SerializeOptions{
		RpmDownloader: mg.rpmDownloader,
	}

	mf, err := preManifest.Serialize(depsolved, containerSpecs, commitSpecs, flatpakSpecs, opts)
	if err != nil {
		return Result{}, err
	}

	// The rpmlist needs full depsolve records; the returned inventory must
	// project away repository credentials and download URLs.
	payload := preManifest.PayloadPipelines()
	packages := payloadPackages(payload, depsolved)
	if mg.rpmlistWriter != nil {
		if err := writeRPMList(mg.rpmlistWriter, packages); err != nil {
			return Result{}, err
		}
	}

	return Result{Manifest: mf, Packages: sbomPackages(packages)}, nil
}

// payloadPackages returns the union of depsolved payload RPMs (including
// extras), sorted by full NEVRA. Buildroot pipelines are excluded.
// A package recorded twice with the same checksum is
// kept once.
//
// The returned records are the full depsolve packages. Callers that persist
// them (the SBOM sidecar) must project onto sbom.Package instead.
func payloadPackages(payload []string, depsolved map[string]depsolvednf.DepsolveResult) rpmmd.PackageList {
	unique := make(map[string]rpmmd.Package)
	// XXX: this is very similar to
	// osbuild-composer:jobimpl-osbuild.go, see if code
	// can be shared
	for plName, pipeline := range depsolved {
		if !slices.Contains(payload, plName) {
			continue
		}
		addUniquePackagesFromPipeline(unique, pipeline)
	}
	packages := make(rpmmd.PackageList, 0, len(unique))
	for _, pkg := range unique {
		packages = append(packages, pkg)
	}
	// The packages were collected from a map keyed by pipeline name, so their
	// order is otherwise random. Sort them so sidecars and SBOMs are stable.
	slices.SortFunc(packages, func(a, b rpmmd.Package) int {
		return cmp.Or(
			cmp.Compare(a.FullNEVRA(), b.FullNEVRA()),
			cmp.Compare(a.Checksum.Value, b.Checksum.Value),
		)
	})
	return packages
}

// sbomPackages copies only the fields an SBOM needs. Repository credentials,
// client-certificate paths, and download URLs on the depsolve records are dropped.
func sbomPackages(packages rpmmd.PackageList) []sbom.Package {
	out := make([]sbom.Package, len(packages))
	for i, pkg := range packages {
		out[i] = sbom.PackageFromRPMMD(pkg)
	}
	return out
}

func addUniquePackagesFromPipeline(unique map[string]rpmmd.Package, pipeline depsolvednf.DepsolveResult) {
	for _, pkg := range pipeline.Transactions.AllPackages() {
		var key string
		key = pkg.Checksum.Value
		if pkg.Checksum.Value == "" {
			key = fmt.Sprintf("%s-%s-%s.%s", pkg.Name, pkg.Version, pkg.Release, pkg.Arch)
		}
		if _, exists := unique[key]; !exists {
			unique[key] = pkg
		}
	}
}

func writeRPMList(writer RPMListWriterFunc, packages rpmmd.PackageList) error {
	rpmListJSON, err := rpmlist.EncodePackages(packages)
	if err != nil {
		return err
	}
	return writer("rpmlist.json", rpmListJSON)
}

func xdgCacheHome() (string, error) {
	xdgCacheHome := os.Getenv("XDG_CACHE_HOME")
	if xdgCacheHome != "" {
		return xdgCacheHome, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache"), nil
}

// DefaultDepsolve provides a default implementation for depsolving.
// It should rarely be necessary to use it directly and will be used
// by default by manifestgen (unless overriden)
//
// The customSolver argument can be nil
func DefaultDepsolve(solver *depsolvednf.Solver, cacheDir string, depsolveWarningsOutput io.Writer, packageSets map[string][]rpmmd.PackageSet, d distro.Distro, arch string) (map[string]depsolvednf.DepsolveResult, error) {
	if solver == nil {
		return nil, fmt.Errorf("need a valid solver, got nil")
	}
	if depsolveWarningsOutput != nil {
		solver.Stderr = depsolveWarningsOutput
	}

	return solver.DepsolveAll(packageSets)
}

type (
	DepsolveFunc func(solver *depsolvednf.Solver, cacheDir string, depsolveWarningsOutput io.Writer, packageSets map[string][]rpmmd.PackageSet, d distro.Distro, arch string) (map[string]depsolvednf.DepsolveResult, error)

	ContainerResolverFunc func(containerSources map[string][]container.SourceSpec, archName string) (map[string][]container.Spec, error)

	CommitResolverFunc func(commitSources map[string][]ostree.SourceSpec) (map[string][]ostree.CommitSpec, error)

	FlatpakResolverFunc func(flatpakSources map[string][]flatpak.SourceSpec) (map[string][]flatpak.Spec, error)

	RPMListWriterFunc func(filename string, content io.Reader) error
)
