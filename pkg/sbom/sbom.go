package sbom

import (
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/google/uuid"
	"github.com/protobom/protobom/pkg/formats"
	pb "github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// SBOM is a single software bill of materials document. Create one with
// Generate and serialize it with Write.
type SBOM struct{ doc *pb.Document }

// ToolInfo identifies the program that created an SBOM.
type ToolInfo struct {
	// Name is the tool name, e.g. "image-builder".
	Name string

	// Version is the tool version.
	Version string
}

// Creator identifies who and what created an SBOM.
type Creator struct {
	// Tool is the program that created the SBOM.
	Tool ToolInfo

	// Organization is the organization that created the SBOM, e.g. "Red Hat".
	// Empty means no Organization creator is recorded.
	Organization string
}

// Image identifies the built image the SBOM describes.
type Image struct {
	// Name is the image package name, supplied by the caller. It is not a file
	// name, e.g. "centos-9-qcow2-x86_64". It is also the SPDX document name.
	Name string

	// FileName is the image file name as saved to disk, e.g.
	// "centos-9-qcow2-x86_64.qcow2".
	FileName string

	// SHA256 is the lowercase hex SHA-256 digest of the image file.
	SHA256 string
}

// Inputs is everything Generate needs to build an image-rooted SBOM.
type Inputs struct {
	// Creator identifies who and what created the SBOM.
	Creator Creator

	// Image is the built image the document describes.
	Image Image

	// Packages is the caller-supplied RPM inventory, not necessarily a full
	// image inventory. Empty is valid for an image-only document.
	Packages []Package
}

// Format identifies a serialization supported by Write. It exists so callers
// never need to import protobom or its formats package.
type Format string

const (
	FormatSPDX23JSON Format = "spdx-2.3-json"
)

// Generate builds an SBOM for a built image and its package set. The document
// is rooted at the image: it DESCRIBES the image and the image CONTAINS a node
// for each package. Call it once the image's SHA-256 is known; there is no
// earlier manifest-rooted document to rewrite.
func Generate(in Inputs) (*SBOM, error) {
	if in.Image.Name == "" {
		return nil, errors.New("image name is missing")
	}
	if err := validateSHA256(in.Image.SHA256); err != nil {
		return nil, err
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
	ns, err := documentNamespace(in.Image.Name)
	if err != nil {
		return nil, err
	}
	doc.Metadata.Id = ns

	image := imageNode(in.Image, in.Creator.Organization)
	doc.NodeList.AddRootNode(image)

	rpms, err := rpmNodes(in.Packages)
	if err != nil {
		return nil, err
	}
	for _, rpm := range rpms {
		doc.NodeList.AddNode(rpm)
		doc.NodeList.AddEdge(&pb.Edge{
			Type: pb.Edge_contains,
			From: image.Id,
			To:   []string{rpm.Id},
		})
	}

	return &SBOM{doc: doc}, nil
}

// Write serializes the SBOM to w in the given format.
func (s *SBOM) Write(w io.Writer, f Format) error {
	if f != FormatSPDX23JSON {
		return fmt.Errorf("unsupported SBOM format %q", f)
	}
	return writer.New().WriteStreamWithOptions(s.doc, w, &writer.Options{Format: formats.SPDX23JSON})
}

// documentNamespace is the SPDX namespace for a document:
// https://osbuild.org/spdxdocs/[DocumentName]-[UUID]. The UUID is random, so
// each document gets its own namespace.
func documentNamespace(name string) (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generating document namespace: %w", err)
	}
	return "https://osbuild.org/spdxdocs/" + url.PathEscape(name) + "-" + id.String(), nil
}

// imageNode builds the package node for the built image. Its SPDX ID is derived
// from "image\n" plus the image's SHA-256, not from its name.
func imageNode(image Image, organization string) *pb.Node {
	node := &pb.Node{
		Id:       nodeID("image\n" + image.SHA256),
		Type:     pb.Node_PACKAGE,
		Name:     image.Name,
		FileName: image.FileName,
		Hashes: map[int32]string{
			int32(pb.HashAlgorithm_SHA256): image.SHA256,
		},
	}
	if organization != "" {
		node.Suppliers = []*pb.Person{{Name: organization, IsOrg: true}}
	}
	return node
}

// nodeID gives nodes stable identities within a document: RPMs use their purl,
// images use a distinct prefix and artifact digest. SPDX IDs are document-scoped;
// the random document namespace keeps separate generations distinct.
func nodeID(v string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(v)).String()
}

// validateSHA256 reports whether s is a SHA-256 digest: 64 lowercase hex characters.
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
