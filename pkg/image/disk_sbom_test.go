package image_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osbuild/image-builder/internal/testdisk"
	"github.com/osbuild/image-builder/pkg/arch"
	"github.com/osbuild/image-builder/pkg/depsolvednf"
	"github.com/osbuild/image-builder/pkg/image"
	"github.com/osbuild/image-builder/pkg/manifest"
	"github.com/osbuild/image-builder/pkg/platform"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/osbuild/image-builder/pkg/runner"
)

func TestSBOMReachableFromDiskAndSysextExports(t *testing.T) {
	img := image.NewDiskImage(&platform.Data{Arch: arch.ARCH_X86_64, ImageFormat: platform.FORMAT_RAW}, "disk.raw")
	img.DiskCustomizations = manifest.NewDiskCustomizations()
	img.PartitionTable = testdisk.MakeFakePartitionTable("/")
	img.Sysexts = []image.SysextConfig{{
		Name: "test", Format: "erofs",
		PackageSet: rpmmd.PackageSet{Include: []string{"extension"}},
	}}
	mf := manifest.New()
	primary, err := img.InstantiateManifest(&mf, nil, &runner.Fedora{}, nil)
	require.NoError(t, err)

	// Even when only the primary artifact is requested, instantiation sets up
	// the extension's full pipeline chain and marks its EROFS output exportable.
	extension := image.SysextPipelineName("test", "erofs")
	require.ElementsMatch(t, []string{primary.Export(), extension}, mf.GetExports())
	require.ElementsMatch(t, []string{"os", primary.Export(), "sysext-test-tree", "sysext-test-prep", extension}, mf.PayloadPipelines())
	sets := mockPackageSets()
	sets["sysext-test-tree"] = depsolvednf.DepsolveResult{Transactions: depsolvednf.TransactionList{sets["os"].Transactions[0], {}}}
	wire, err := mf.Serialize(sets, nil, nil, nil, nil)
	require.NoError(t, err)
	graph, err := mf.SBOMGraph(wire, sets, nil, nil, nil)
	require.NoError(t, err)
	names, err := graph.Reachable(primary.Export(), false)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"os", primary.Export()}, names)
	names, err = graph.Reachable(extension, false)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"sysext-test-tree", "sysext-test-prep", extension}, names)
}
