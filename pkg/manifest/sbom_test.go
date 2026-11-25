package manifest_test

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/osbuild/image-builder/pkg/container"
	"github.com/osbuild/image-builder/pkg/depsolvednf"
	"github.com/osbuild/image-builder/pkg/flatpak"
	"github.com/osbuild/image-builder/pkg/manifest"
	"github.com/osbuild/image-builder/pkg/ostree"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/osbuild/image-builder/pkg/runner"
	"github.com/osbuild/image-builder/pkg/sbom"
)

func TestSBOMRequiresRequestedDepsolveResults(t *testing.T) {
	m := manifest.New()
	build := manifest.NewContentTestBuild(&m, nil, nil, nil)
	manifest.NewContentTest("os", build, []rpmmd.PackageSet{{Include: []string{"shell"}}}, nil, nil)
	manifest.NewContentTest("format", build, nil, nil, nil)
	wire := manifest.OSBuildManifest(`{"pipelines":[{"name":"build"},{"name":"os"},{"name":"format"}]}`)
	// Having other content cannot stand in for the requested RPM inventory.
	containers := map[string][]container.Spec{"os": {{LocalName: "source"}}}
	_, err := m.SBOMGraph(wire, nil, containers, nil, nil)
	require.ErrorContains(t, err, `missing depsolve result for pipeline "os"`)
	// A successful, empty transaction is not a missing result. Neither
	// the container buildroot nor the format conversion requested an RPM solve.
	_, err = m.SBOMGraph(wire, map[string]depsolvednf.DepsolveResult{"os": {Transactions: depsolvednf.TransactionList{{}}}}, containers, nil, nil)
	require.NoError(t, err)
}

func TestManifestSBOM(t *testing.T) {
	mf := manifest.New()
	bootstrap := manifest.NewBootstrap(&mf, nil)
	build := manifest.NewBuild(&mf, &runner.Fedora{}, nil, &manifest.BuildOptions{BootstrapPipeline: bootstrap})
	for _, name := range []string{"os", "installer", "container-payload", "ostree-payload", "flatpak-payload"} {
		manifest.NewContentTest(name, build, nil, nil, nil)
	}

	rpm := func(name, hexDigit string) rpmmd.Package {
		return rpmmd.Package{
			Name: name, Version: "1.0", Release: "1.fc44", Arch: "x86_64", Vendor: "Fedora Project",
			Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat(hexDigit, 64)},
		}
	}
	shared := rpm("shared-rpm", "a")
	sets := map[string]depsolvednf.DepsolveResult{
		build.Name(): {Transactions: depsolvednf.TransactionList{{rpm("build-tool", "b")}}},
		"os":         {Transactions: depsolvednf.TransactionList{{shared}, {rpm("second-transaction-rpm", "c")}}},
		"installer":  {Transactions: depsolvednf.TransactionList{{shared}}},
	}

	containerSpec := container.Spec{LocalName: "payload-image", Source: "registry.example.test/payload/image", Digest: "sha256:" + strings.Repeat("d", 64)}
	localContainer := container.Spec{LocalName: "local-image", Source: "localhost/payload/image", Digest: "sha256:" + strings.Repeat("2", 64), LocalStorage: true}
	commitSpec := ostree.CommitSpec{Ref: "fedora/x86_64/edge", URL: "https://example.test/ostree", Checksum: strings.Repeat("e", 64)}
	flatpakContainer := container.Spec{LocalName: "org.example.Container", Source: "registry.example.test/flatpak/app", Digest: "sha256:" + strings.Repeat("f", 64)}
	flatpakCommit := ostree.CommitSpec{Ref: "app/org.example.Commit/x86_64/stable", URL: "https://example.test/flatpak", Checksum: strings.Repeat("1", 64)}
	bootstrapSpec := container.Spec{LocalName: "bootstrap-image", Source: "registry.example.test/bootstrap/image", Digest: "sha256:" + strings.Repeat("3", 64)}
	containers := map[string][]container.Spec{
		"container-payload": {containerSpec, localContainer},
		bootstrap.Name():    {bootstrapSpec},
	}
	commits := map[string][]ostree.CommitSpec{"ostree-payload": {commitSpec}}
	flatpaks := map[string][]flatpak.Spec{"flatpak-payload": {{ContainerSpec: &flatpakContainer}, {CommitSpec: &flatpakCommit}}}
	in := sbom.Inputs{Image: sbom.Image{Name: "test-image"}, Creator: sbom.Creator{Tool: sbom.ToolInfo{Name: "image-builder", Version: "1.2.3"}}}

	// Include a transit-only pipeline and all three supported pipeline reference shapes.
	manifest.NewContentTest("disk", build, nil, nil, nil)
	wire := manifest.OSBuildManifest(`{"pipelines":[
		{"name":"build","build":"name:bootstrap-buildroot"}, {"name":"bootstrap-buildroot"},
		{"name":"os"}, {"name":"installer"}, {"name":"container-payload"},
		{"name":"ostree-payload"}, {"name":"flatpak-payload"},
		{"name":"disk","build":"name:build","stages":[{"inputs":{
			"tree":{"origin":"org.osbuild.pipeline","references":["name:os","name:container-payload","name:flatpak-payload"]},
			"files":{"origin":"org.osbuild.pipeline","references":[{"id":"name:installer","options":{}}]},
			"commit":{"origin":"org.osbuild.pipeline","references":{"name:ostree-payload":{}}},
			"source":{"origin":"org.osbuild.source","references":["name:not-a-pipeline"]}
		}}]}
	]}`)
	graph, err := mf.SBOMGraph(wire, sets, containers, commits, flatpaks)
	require.NoError(t, err)
	t.Run("primary image", func(t *testing.T) {
		doc, err := graph.Document(in, "disk", false)
		require.NoError(t, err)
		nodes := assertSBOMGraph(t, doc, in.Image.Name, map[string][]string{
			in.Image.Name:       {"disk"},
			"disk":              {"os", "installer", "ostree-payload", "container-payload", "flatpak-payload"},
			"os":                {shared.Name, "second-transaction-rpm"},
			"installer":         {shared.Name},
			"container-payload": {containerSpec.LocalName, localContainer.LocalName},
			"ostree-payload":    {commitSpec.Ref},
			"flatpak-payload":   {flatpakContainer.LocalName, flatpakCommit.Ref},
		})

		for _, want := range []struct{ name, location, digest string }{
			{containerSpec.LocalName, "docker://" + containerSpec.Source + "@" + containerSpec.Digest, containerSpec.Digest},
			{localContainer.LocalName, "", localContainer.Digest},
			{commitSpec.Ref, commitSpec.URL, "sha256:" + commitSpec.Checksum},
			{flatpakContainer.LocalName, "docker://" + flatpakContainer.Source + "@" + flatpakContainer.Digest, flatpakContainer.Digest},
			{flatpakCommit.Ref, flatpakCommit.URL, "sha256:" + flatpakCommit.Checksum},
		} {
			node := nodes[want.name]
			require.NotNil(t, node, "missing %s", want.name)
			assert.Equal(t, want.location, node.GetUrlDownload(), want.name)
			assert.Equal(t, want.digest, node.GetVersion(), want.name)
			assert.Equal(t, strings.TrimPrefix(want.digest, "sha256:"), node.GetHashes()[int32(pb.HashAlgorithm_SHA256)], want.name)
		}
	})

	t.Run("buildroot only", func(t *testing.T) {
		buildInput := in
		buildInput.Image.Name = "test-buildroot"
		doc, err := graph.Document(buildInput, build.Name(), true)
		require.NoError(t, err)
		assertSBOMGraph(t, doc, buildInput.Image.Name, map[string][]string{
			buildInput.Image.Name: {build.Name()},
			build.Name():          {"build-tool", bootstrap.Name()},
			bootstrap.Name():      {bootstrapSpec.LocalName},
		})
	})

	t.Run("buildroot also supplies artifact bytes", func(t *testing.T) {
		// Like Aboot's write-device stage: build is both an execution environment
		// and the source of a copied file. Only the latter edge survives.
		disk := manifest.OSBuildManifest(`{"pipelines":[{"name":"build","build":"name:bootstrap-buildroot"},{"name":"bootstrap-buildroot"},{"name":"disk","build":"name:build","stages":[{"inputs":{"bootloader":{"origin":"org.osbuild.pipeline","references":["name:build"]}}}]}]}`)
		graph, err := mf.SBOMGraph(disk, sets, nil, nil, nil)
		require.NoError(t, err)
		doc, err := graph.Document(in, "disk", false)
		require.NoError(t, err)
		nodes := assertSBOMGraph(t, doc, in.Image.Name, map[string][]string{in.Image.Name: {"disk"}, "disk": {"build"}, "build": {"build-tool"}})
		assert.Equal(t, "buildroot", nodes["build"].Description)
	})

	t.Run("malformed source digest", func(t *testing.T) {
		invalid := containerSpec
		invalid.Digest = "sha256:abcd"
		graph, err := mf.SBOMGraph(wire, sets, map[string][]container.Spec{"container-payload": {invalid}}, nil, nil)
		require.NoError(t, err)
		doc, err := graph.Document(in, "container-payload", false)
		require.ErrorContains(t, err, `pipeline "container-payload": invalid container digest`)
		assert.Nil(t, doc)
	})

	t.Run("empty pipeline references", func(t *testing.T) {
		for _, item := range []string{`null`, `""`, `{}`} {
			wire := manifest.OSBuildManifest(`{"pipelines":[{"name":"disk","stages":[{"inputs":{"tree":{"origin":"org.osbuild.pipeline","references":[` + item + `]}}}]}]}`)
			_, err := mf.SBOMGraph(wire, sets, nil, nil, nil)
			require.ErrorContains(t, err, `pipeline "disk" inputs: empty pipeline reference`)
		}
	})

	t.Run("unknown pipeline", func(t *testing.T) {
		doc, err := graph.Document(in, "typo", false)
		require.ErrorContains(t, err, `unknown SBOM pipeline "typo"`)
		assert.Nil(t, doc)
	})
}

func assertSBOMGraph(t *testing.T, doc *sbom.Document, rootName string, wantChildren map[string][]string) map[string]*pb.Node {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, doc.WriteProto(&buf))
	var graph pb.Document
	require.NoError(t, proto.Unmarshal(buf.Bytes(), &graph))
	roots := graph.GetRootNodes()
	require.Len(t, roots, 1)
	assert.Equal(t, rootName, roots[0].GetName())

	byID, byName := map[string]*pb.Node{}, map[string]*pb.Node{}
	for _, node := range graph.GetNodeList().GetNodes() {
		require.NotContains(t, byID, node.GetId(), "duplicate node ID for %q", node.GetName())
		if prev := byName[node.GetName()]; prev != nil {
			require.Equal(t, "shared-rpm", node.GetName())
			require.NotEqual(t, prev.Id, node.Id)
		}
		byID[node.GetId()], byName[node.GetName()] = node, node
	}

	wantNames := map[string]bool{}
	for parent, children := range wantChildren {
		wantNames[parent] = true
		for _, child := range children {
			wantNames[child] = true
		}
	}
	assert.Len(t, byName, len(wantNames))
	for name := range wantNames {
		assert.Contains(t, byName, name)
	}

	gotChildren := map[string][]string{}
	for _, edge := range graph.GetNodeList().GetEdges() {
		require.Contains(t, []pb.Edge_Type{pb.Edge_contains, pb.Edge_buildTool, pb.Edge_prerequisite}, edge.GetType())
		from := byID[edge.GetFrom()]
		require.NotNil(t, from, "unknown edge source %q", edge.GetFrom())
		for _, id := range edge.GetTo() {
			to := byID[id]
			require.NotNil(t, to, "unknown edge target %q", id)
			parent, child := from, to
			if edge.Type == pb.Edge_buildTool {
				parent, child = to, from
				assert.Equal(t, "buildroot", child.Description)
			}
			if parent.Name == "disk" {
				assert.Equal(t, pb.Edge_prerequisite, edge.Type)
			}
			gotChildren[parent.GetName()] = append(gotChildren[parent.GetName()], child.GetName())
		}
	}
	assert.Len(t, gotChildren, len(wantChildren))
	for parent, children := range wantChildren {
		assert.ElementsMatch(t, children, gotChildren[parent], "children of %q", parent)
	}
	return byName
}
