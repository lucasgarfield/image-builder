package sbom

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"

	"github.com/google/uuid"
	"github.com/osbuild/image-builder/pkg/container"
	"github.com/osbuild/image-builder/pkg/flatpak"
	"github.com/osbuild/image-builder/pkg/ostree"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/formats"
	pb "github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ToolInfo identifies the program that created an SBOM.
type ToolInfo struct {
	Name    string
	Version string
}

// Creator identifies who and what created an SBOM.
type Creator struct {
	Tool ToolInfo

	// Organization is the organization that created the SBOM, e.g. "Red Hat".
	// Empty means no Organization creator is recorded.
	Organization string
}

// Image identifies the built image the SBOM describes.
type Image struct {
	// Name is the image package name, supplied by the caller, e.g. "centos-9-qcow2-x86_64". It becomes the SPDX document name.
	Name string

	// Version is the caller's image version, if known (not the builder version).
	Version string

	// Purpose defaults to OPERATING-SYSTEM for a built image.
	Purpose pb.Purpose

	// FileName is the image file name as saved to disk, e.g.
	// "centos-9-qcow2-x86_64.qcow2".
	FileName string

	// SHA256, if known, is the lowercase hex SHA-256 digest of the image file.
	SHA256 string
}

// Inputs is everything Generate needs to build an image-rooted SBOM.
type Inputs struct {
	Creator Creator
	Image   Image

	// Pipelines holds the resolved content of each pipeline in this document.
	Pipelines map[string]Pipeline
}

type PipelineRole string

const (
	PipelinePayload   PipelineRole = "payload"
	PipelineBuildroot PipelineRole = "buildroot"
	PipelineArtifact  PipelineRole = "artifact"
)

// Pipeline describes pinned build inputs, not just the installed RPMs.
type Pipeline struct {
	// Role distinguishes build environments, payloads, and exported artifacts.
	Role PipelineRole
	// Inputs contribute payload. BuildInputs (execution environments and
	// reference trees for deltas) are needed to build it but aren't included.
	Inputs      []string
	BuildInputs []string
	Packages    []rpmmd.Package
	Containers  []container.Spec
	Commits     []ostree.CommitSpec
	Flatpaks    []flatpak.Spec
}

// Format identifies a serialization supported by Write.
type Format string

const (
	FormatSPDX23JSON Format = "spdx-2.3-json"
)

// Generate constructs an image-rooted graph before or after the image is built.
func Generate(in Inputs) (*Document, error) {
	if in.Image.Name == "" {
		return nil, errors.New("image name is missing")
	}
	if in.Image.SHA256 != "" {
		if err := validateSHA256(in.Image.SHA256); err != nil {
			return nil, err
		}
	}
	if in.Creator.Tool.Name == "" {
		return nil, errors.New("tool name is missing")
	}
	if in.Creator.Tool.Version == "" {
		return nil, errors.New("tool version is missing")
	}

	doc := pb.NewDocument()
	doc.Metadata.Tools = append(doc.Metadata.Tools, &pb.Tool{Name: in.Creator.Tool.Name, Version: in.Creator.Tool.Version})
	if in.Creator.Organization != "" {
		doc.Metadata.Authors = append(doc.Metadata.Authors, &pb.Person{Name: in.Creator.Organization, IsOrg: true})
	}

	doc.Metadata.Name = in.Image.Name
	doc.Metadata.Date = timestamppb.Now()
	ns, err := documentNamespace(in.Image.Name)
	if err != nil {
		return nil, err
	}
	doc.Metadata.Id = ns

	image := imageNode(in.Image, in.Creator.Organization)
	doc.NodeList.AddRootNode(image)

	referenced := map[string]bool{}
	for _, p := range in.Pipelines {
		for _, dep := range p.Inputs {
			referenced[dep] = true
		}
		for _, dep := range p.BuildInputs {
			referenced[dep] = true
		}
	}
	pipelineID := func(name string) string { return nodeID("pipeline\n" + name) }
	seen := make(map[string]*pb.Node)
	for _, name := range slices.Sorted(maps.Keys(in.Pipelines)) {
		p := in.Pipelines[name]
		pipeline := &pb.Node{Id: pipelineID(name), Type: pb.Node_PACKAGE, Name: name, Summary: "osbuild pipeline", Description: string(p.Role)}
		doc.NodeList.AddNode(pipeline)
		if !referenced[name] {
			doc.NodeList.AddEdge(&pb.Edge{Type: pb.Edge_contains, From: image.Id, To: []string{pipeline.Id}})
		}
		for _, input := range p.Inputs {
			if _, ok := in.Pipelines[input]; !ok {
				return nil, fmt.Errorf("pipeline %q: unknown input %q", name, input)
			}
			doc.NodeList.AddEdge(&pb.Edge{Type: pb.Edge_prerequisite, From: pipeline.Id, To: []string{pipelineID(input)}})
		}
		for _, dep := range p.BuildInputs {
			if _, ok := in.Pipelines[dep]; !ok {
				return nil, fmt.Errorf("pipeline %q: unknown build input %q", name, dep)
			}
			doc.NodeList.AddEdge(&pb.Edge{Type: pb.Edge_buildTool, From: pipelineID(dep), To: []string{pipeline.Id}})
		}
		nodes, err := p.nodes(name)
		if err != nil {
			return nil, fmt.Errorf("pipeline %q: %w", name, err)
		}
		var children []string
		local := map[string]bool{}
		for _, n := range nodes {
			if prior := seen[n.Id]; prior == nil {
				seen[n.Id] = n
				doc.NodeList.AddNode(n)
			} else if !maps.Equal(prior.Hashes, n.Hashes) {
				return nil, fmt.Errorf("conflicting checksums for %q", n.Name)
			}
			if !local[n.Id] {
				children = append(children, n.Id)
				local[n.Id] = true
			}
		}
		for _, edge := range rpmDependencies(name, p.Packages) {
			doc.NodeList.AddEdge(edge)
		}
		if len(children) > 0 {
			doc.NodeList.AddEdge(&pb.Edge{Type: pb.Edge_contains, From: pipeline.Id, To: children})
		}
	}

	// Missing license or copyright metadata is not evidence that none applies.
	for _, n := range doc.NodeList.Nodes {
		if len(n.Licenses) == 0 {
			n.Licenses = []string{"NOASSERTION"}
		}
		if n.LicenseConcluded == "" {
			n.LicenseConcluded = "NOASSERTION"
		}
		if n.Copyright == "" {
			n.Copyright = "NOASSERTION"
		}
	}
	return &Document{doc: doc}, nil
}

// WriteProto preserves the document's identity and relationships between build steps.
func (s *Document) WriteProto(w io.Writer) error {
	b, err := proto.Marshal(s.doc)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadProto restores the image-rooted document saved by WriteProto.
func ReadProto(r io.Reader) (*Document, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	doc := new(pb.Document)
	if err := proto.Unmarshal(b, doc); err != nil {
		return nil, err
	}
	if doc.Metadata.GetId() == "" || doc.NodeList == nil || len(doc.NodeList.RootElements) != 1 || doc.NodeList.GetNodeByID(doc.NodeList.RootElements[0]) == nil {
		return nil, errors.New("invalid SBOM document: missing identity or image root")
	}
	return &Document{doc: doc}, nil
}

// SetArtifact records the built file without changing the pre-build document identity.
func (s *Document) SetArtifact(fileName, sha256 string) error {
	if err := validateSHA256(sha256); err != nil {
		return err
	}
	if s == nil || s.doc.GetNodeList() == nil || len(s.doc.NodeList.RootElements) != 1 {
		return errors.New("cannot set artifact: missing or ambiguous image root")
	}
	root := s.doc.NodeList.GetNodeByID(s.doc.NodeList.RootElements[0])
	if root == nil {
		return errors.New("cannot set artifact: missing image root")
	}
	if fileName == "" {
		return errors.New("artifact filename is missing")
	}
	if root.FileName != "" && root.FileName != fileName {
		return fmt.Errorf("artifact filename is already %q", root.FileName)
	}
	const algorithm = int32(pb.HashAlgorithm_SHA256)
	if existing, ok := root.Hashes[algorithm]; ok && existing != sha256 {
		return errors.New("artifact SHA-256 conflicts with existing digest")
	}
	if root.Hashes == nil {
		root.Hashes = make(map[int32]string)
	}
	root.Hashes[algorithm] = sha256
	root.FileName = fileName
	return nil
}

// Write serializes the SBOM to w in the given format.
func (s *Document) Write(w io.Writer, f Format) error {
	if f != FormatSPDX23JSON {
		return fmt.Errorf("unsupported SBOM format %q", f)
	}
	return writer.New().WriteStreamWithOptions(s.doc, w, &writer.Options{Format: formats.SPDX23JSON})
}

// documentNamespace appends a random UUID so each document gets a unique
// SPDX namespace, as SPDX 2.3 requires:
// https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#65-spdx-document-namespace-field
func documentNamespace(name string) (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generating document namespace: %w", err)
	}
	return "https://osbuild.org/spdxdocs/" + url.PathEscape(name) + "-" + id.String(), nil
}

// imageNode builds the package node for the built image.
func imageNode(image Image, organization string) *pb.Node {
	purpose := image.Purpose
	if purpose == pb.Purpose_UNKNOWN_PURPOSE {
		purpose = pb.Purpose_OPERATING_SYSTEM
	}
	purl := packageurl.NewPackageURL(packageurl.TypeGeneric, "", image.Name, image.Version, nil, "").ToString()
	node := &pb.Node{
		// The SPDX writer adds the SPDXRef- prefix to the protobom element ID.
		Id:             "Image",
		Version:        image.Version,
		PrimaryPurpose: []pb.Purpose{purpose},
		Identifiers:    map[int32]string{int32(pb.SoftwareIdentifierType_PURL): purl},
		Type:           pb.Node_PACKAGE,
		Name:           image.Name,
		FileName:       image.FileName,
	}
	if image.SHA256 != "" {
		node.Hashes = map[int32]string{int32(pb.HashAlgorithm_SHA256): image.SHA256}
	}
	if organization != "" {
		node.Suppliers = []*pb.Person{{Name: organization, IsOrg: true}}
	}
	return node
}

// nodeID gives nodes stable identities within a document.
func nodeID(v string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(v)).String()
}

func validateSHA256(s string) error {
	if s == "" {
		return errors.New("image sha256 is missing")
	}
	if len(s) != 64 {
		return fmt.Errorf("invalid image sha256 %q", s)
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("invalid image sha256 %q", s)
		}
	}
	return nil
}
