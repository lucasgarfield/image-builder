package manifest_test

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/osbuild/image-builder/pkg/depsolvednf"
	"github.com/osbuild/image-builder/pkg/manifest"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/osbuild/image-builder/pkg/sbom"
)

func TestSBOMSysextReference(t *testing.T) {
	base := rpmmd.Package{Repo: &rpmmd.RepoConfig{Id: "test-repo"}, Name: "base-only", Version: "1", Release: "1", Arch: "noarch", Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("a", 64)}, RemoteLocations: []string{"https://example.org/base.rpm"}}
	extra := base
	extra.Name = "extension-only"
	extra.Checksum.Value = strings.Repeat("b", 64)
	extra.RemoteLocations = []string{"https://example.org/extension.rpm"}
	m := manifest.New()
	build := manifest.NewContentTestBuild(&m, nil, nil, nil)
	ref := manifest.NewContentTest("os", build, []rpmmd.PackageSet{{Include: []string{base.Name}}}, nil, nil)
	sp := manifest.NewSysextPipelines(build, nil, nil, ref, ref, "example")
	sp.Tree.Customizations.PackageSet.Include = []string{extra.Name}
	in := sbom.Inputs{Image: sbom.Image{Name: "extension"}, Creator: sbom.Creator{Tool: sbom.ToolInfo{Name: "test", Version: "1"}}}
	for _, tc := range []struct {
		name string
		last rpmmd.PackageList
	}{{"new packages", rpmmd.PackageList{extra}}, {"empty final transaction", rpmmd.PackageList{}}} {
		t.Run(tc.name, func(t *testing.T) {
			sets := map[string]depsolvednf.DepsolveResult{ref.Name(): {Transactions: depsolvednf.TransactionList{{base}}}, sp.Tree.Name(): {Transactions: depsolvednf.TransactionList{{base}, tc.last}}}
			wire, err := m.Serialize(sets, nil, nil, nil, nil)
			require.NoError(t, err)
			g, err := m.SBOMGraph(wire, sets, nil, nil, nil)
			require.NoError(t, err)
			for _, withBuild := range []bool{false, true} {
				doc, err := g.Document(in, sp.Prep.Name(), withBuild)
				require.NoError(t, err)
				var buf bytes.Buffer
				require.NoError(t, doc.WriteProto(&buf))
				var graph pb.Document
				require.NoError(t, proto.Unmarshal(buf.Bytes(), &graph))
				ids := map[string]string{}
				for _, n := range graph.NodeList.Nodes {
					require.NotContains(t, ids, n.Name, "RPM must not be repeated in the extension tree")
					ids[n.Name] = n.Id
				}
				require.Equal(t, len(tc.last) > 0, ids[extra.Name] != "")
				require.Equal(t, withBuild, ids[base.Name] != "")
				require.Equal(t, withBuild, ids[ref.Name()] != "")
				if withBuild {
					var consumers []string
					for _, e := range graph.NodeList.Edges {
						if e.From == ids[ref.Name()] && e.Type == pb.Edge_buildTool {
							consumers = append(consumers, e.To...)
						}
					}
					require.ElementsMatch(t, []string{ids[sp.Prep.Name()], ids[sp.Tree.Name()]}, consumers)
				}
			}
			sets[sp.Tree.Name()] = depsolvednf.DepsolveResult{Transactions: depsolvednf.TransactionList{{base, extra}}}
			_, err = m.SBOMGraph(wire, sets, nil, nil, nil)
			require.ErrorContains(t, err, "expected 2 depsolve transactions, got 1")
			delete(sets, sp.Tree.Name())
			_, err = m.SBOMGraph(wire, sets, nil, nil, nil)
			require.ErrorContains(t, err, `missing depsolve result for pipeline "sysext-example-tree"`)
		})
	}
}
