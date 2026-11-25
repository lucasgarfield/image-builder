package sbom_test

import (
	"bytes"
	"strings"
	"testing"

	pb "github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/osbuild/image-builder/pkg/ostree"
	"github.com/osbuild/image-builder/pkg/sbom"
)

func TestDocumentProtoRoundTripAndSetArtifact(t *testing.T) {
	commit := ostree.CommitSpec{Ref: "fedora/x86_64/edge", URL: "https://example.test/ostree", Checksum: strings.Repeat("a", 64)}
	in := sbom.Inputs{
		Creator: sbom.Creator{Tool: sbom.ToolInfo{Name: "image-builder", Version: "1.2.3"}, Organization: "Example"},
		Image:   sbom.Image{Name: "image before build"},
		Pipelines: map[string]sbom.Pipeline{
			"payload": {Commits: []ostree.CommitSpec{commit}},
		},
	}
	doc, err := sbom.Generate(in)
	require.NoError(t, err)
	before := writeSPDX(t, doc)
	assertDocumentNamespace(t, "image%20before%20build", before.DocumentNamespace)
	root := packageNamed(t, before, in.Image.Name)
	pipeline := packageNamed(t, before, "payload")
	payload := packageNamed(t, before, commit.Ref)
	assert.Empty(t, root.PackageFileName)
	assert.Empty(t, root.Checksums)
	assert.ElementsMatch(t, []spdxRelationship{
		{before.SPDXID, root.SPDXID, "DESCRIBES"},
		{root.SPDXID, pipeline.SPDXID, "CONTAINS"},
		{pipeline.SPDXID, payload.SPDXID, "CONTAINS"},
	}, before.Relationships)

	roundTrip := func(doc *sbom.Document) *sbom.Document {
		t.Helper()
		var buf bytes.Buffer
		require.NoError(t, doc.WriteProto(&buf))
		restored, err := sbom.ReadProto(&buf)
		require.NoError(t, err)
		return restored
	}
	assertSPDXEqual := func(want, got spdxDoc) {
		t.Helper()
		assert.ElementsMatch(t, want.Packages, got.Packages)
		assert.ElementsMatch(t, want.Relationships, got.Relationships)
		want.Packages, got.Packages = nil, nil
		want.Relationships, got.Relationships = nil, nil
		// Protobom's SPDX 2.3 writer timestamps the export, independently of the protobuf creation date.
		want.CreationInfo.Created, got.CreationInfo.Created = "", ""
		assert.Equal(t, want, got)
	}

	restored := roundTrip(doc)
	assertSPDXEqual(before, writeSPDX(t, restored))

	for _, bad := range []string{"", "ba", strings.Repeat("A", 64), strings.Repeat("z", 64)} {
		assert.Error(t, restored.SetArtifact("invalid.raw", bad))
		assertSPDXEqual(before, writeSPDX(t, restored))
	}

	fileName, digest := "disk.raw", strings.Repeat("b", 64)
	require.NoError(t, restored.SetArtifact(fileName, digest))
	// Adding the artifact may only change the image root's file metadata.
	for i := range before.Packages {
		if before.Packages[i].SPDXID == root.SPDXID {
			before.Packages[i].PackageFileName = fileName
			before.Packages[i].Checksums = []spdxChecksum{{"SHA256", digest}}
		}
	}
	assertSPDXEqual(before, writeSPDX(t, restored))
	assertSPDXEqual(before, writeSPDX(t, roundTrip(restored)))
}

func TestSetArtifactPreservesExistingEvidence(t *testing.T) {
	const name = "disk.raw"
	digest := strings.Repeat("d", 64)
	for _, empty := range []*sbom.Document{nil, {}} {
		require.Error(t, empty.SetArtifact(name, digest))
	}
	doc, err := sbom.Generate(testInputs)
	require.NoError(t, err)
	var wire bytes.Buffer
	require.NoError(t, doc.WriteProto(&wire))
	var graph pb.Document
	require.NoError(t, proto.Unmarshal(wire.Bytes(), &graph))
	root := graph.GetRootNodes()[0]
	root.FileName = ""
	other := strings.Repeat("a", 128)
	root.Hashes = map[int32]string{int32(pb.HashAlgorithm_SHA512): other}
	b, err := proto.Marshal(&graph)
	require.NoError(t, err)
	doc, err = sbom.ReadProto(bytes.NewReader(b))
	require.NoError(t, err)
	require.NoError(t, doc.SetArtifact(name, digest))
	require.NoError(t, doc.SetArtifact(name, digest))
	require.Error(t, doc.SetArtifact(name, strings.Repeat("a", 64)))
	require.Error(t, doc.SetArtifact("other.raw", digest))
	image := packageNamed(t, writeSPDX(t, doc), testInputs.Image.Name)
	require.Equal(t, name, image.PackageFileName)
	require.ElementsMatch(t, []spdxChecksum{{"SHA256", digest}, {"SHA512", other}}, image.Checksums)
}

func TestReadProtoRejectsMalformedDocument(t *testing.T) {
	t.Run("invalid wire format", func(t *testing.T) {
		doc, err := sbom.ReadProto(bytes.NewReader([]byte{0x0a, 0x02, 0xff}))
		require.Error(t, err)
		assert.Nil(t, doc)
	})

	for _, tc := range []struct {
		name  string
		graph *pb.Document
	}{
		{"empty message", &pb.Document{}},
		{"missing namespace", &pb.Document{
			NodeList: &pb.NodeList{RootElements: []string{"root"}, Nodes: []*pb.Node{{Id: "root"}}},
		}},
		{"missing root", &pb.Document{
			Metadata: &pb.Metadata{Id: "https://example.test/sbom"},
			NodeList: &pb.NodeList{},
		}},
		{"multiple roots", &pb.Document{
			Metadata: &pb.Metadata{Id: "https://example.test/sbom"},
			NodeList: &pb.NodeList{RootElements: []string{"root1", "root2"}, Nodes: []*pb.Node{{Id: "root1"}, {Id: "root2"}}},
		}},
		{"dangling root", &pb.Document{
			Metadata: &pb.Metadata{Id: "https://example.test/sbom"},
			NodeList: &pb.NodeList{RootElements: []string{"missing"}, Nodes: []*pb.Node{{Id: "root"}}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := proto.Marshal(tc.graph)
			require.NoError(t, err)
			doc, err := sbom.ReadProto(bytes.NewReader(encoded))
			require.Error(t, err)
			assert.Nil(t, doc)
		})
	}
}
