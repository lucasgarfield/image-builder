package sbom

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	pb "github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// SBOM is a single software bill of materials document. Create one with
// Generate, serialize it with Write, load a previously written one with Read,
// and rewrite it to describe a built image with AddImage.
type SBOM struct{ doc *pb.Document }

// ToolInfo identifies the program that created an SBOM.
type ToolInfo struct {
	// Name is the tool name, e.g. "image-builder".
	Name string

	// Version is the tool version.
	Version string
}

// Creator identifies who and what created an SBOM, or added to one.
type Creator struct {
	// Tool is the program that created the SBOM.
	Tool ToolInfo

	// Organization is the organization that created the SBOM, e.g. "Red Hat".
	// Empty means no Organization creator is recorded.
	Organization string
}

// Inputs is everything Generate needs to build a manifest-rooted SBOM.
type Inputs struct {
	// Creator identifies who and what created the SBOM.
	Creator Creator

	// Manifest is the osbuild manifest exactly as it will be written to
	// disk. Its bytes are hashed, so they must match the bytes later passed
	// to AddImage.
	Manifest []byte

	// Name is the manifest package name, supplied by the caller. It is not a
	// file name, e.g. "centos-9-qcow2-x86_64-manifest".
	Name string

	// FileName is the manifest file name as saved to disk, e.g.
	// "centos-9-qcow2-x86_64.osbuild-manifest.json".
	FileName string

	// Packages is the resolved package set installed in the image.
	Packages rpmmd.PackageList
}

// Image identifies a built disk image. After AddImage its node becomes the
// root of the document.
type Image struct {
	// Name is the image package name, supplied by the caller. It is not a file
	// name, e.g. "centos-9-qcow2-x86_64".
	Name string

	// FileName is the image file name as saved to disk, e.g.
	// "centos-9-qcow2-x86_64.qcow2".
	FileName string

	// SHA256 is the hex SHA-256 digest of the image file.
	SHA256 string
}

// Format identifies a serialization supported by Write. It exists so callers
// never need to import protobom or its formats package.
type Format string

const (
	FormatSPDX23JSON Format = "spdx-2.3-json"

	FormatCycloneDXJSON Format = "cyclonedx-json"
)

// Generate builds an SBOM for a manifest and its package set. The document is
// rooted at the manifest: it DESCRIBES the manifest and the manifest CONTAINS
// a node for each package.
//
// The manifest's SHA-256 is computed from in.Manifest, so callers must pass the
// exact bytes they will write to disk.
func Generate(in Inputs) (*SBOM, error) {
	if in.Name == "" {
		return nil, errors.New("manifest name is missing")
	}
	if len(in.Manifest) == 0 {
		return nil, errors.New("manifest is empty")
	}
	if in.Creator.Tool.Name == "" {
		return nil, errors.New("tool name is missing")
	}
	if in.Creator.Tool.Version == "" {
		return nil, errors.New("tool version is missing")
	}

	doc := pb.NewDocument()
	recordTool(doc, in.Creator.Tool)
	recordOrganization(doc, in.Creator.Organization)

	manifestChecksum := checksum(in.Manifest)
	doc.Metadata.Name = in.Name
	ns, err := documentNamespace(in.Name)
	if err != nil {
		return nil, err
	}
	doc.Metadata.Id = ns

	manifest := manifestNode(in.Name, in.FileName, manifestChecksum, in.Creator.Organization)
	doc.NodeList.AddRootNode(manifest)

	// A `pb.Node` with `Type: pb.Node_PACKAGE` comes out as an SPDX package or a CycloneDX component.
	// Merged package lists can name one RPM twice. An exact duplicate is recorded
	// once. The same purl with a different checksum is a conflict.
	seen := map[string]rpmmd.Checksum{}
	for _, p := range in.Packages {
		purl := rpmPURL(p)
		if recorded, ok := seen[purl]; ok {
			if recorded != p.Checksum {
				return nil, fmt.Errorf("duplicate package %q has checksum %s and %s", purl, recorded, p.Checksum)
			}
			continue
		}
		seen[purl] = p.Checksum

		rpm, err := rpmNode(p)
		if err != nil {
			return nil, err
		}
		doc.NodeList.AddNode(rpm)
		doc.NodeList.AddEdge(&pb.Edge{
			Type: pb.Edge_contains,
			From: manifest.Id,
			To:   []string{rpm.Id},
		})
	}

	return &SBOM{doc: doc}, nil
}

// Write serializes the SBOM to w in the given format.
func (s *SBOM) Write(w io.Writer, f Format) error {
	pf, err := toProtobomFormat(f)
	if err != nil {
		return err
	}
	return writer.New().WriteStreamWithOptions(s.doc, w, &writer.Options{Format: pf})
}

// Read parses an SBOM previously written by Write. f must be the format the
// document was serialized as; it is not inferred from the bytes.
func Read(r io.Reader, f Format) (*SBOM, error) {
	pf, err := toProtobomFormat(f)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	rd := reader.New()
	doc, err := rd.ParseStreamWithOptions(bytes.NewReader(data), &reader.Options{Format: pf})
	if err != nil {
		return nil, err
	}
	return &SBOM{doc: doc}, nil
}

// AddImage rewrites the SBOM to describe a built image, making the image the
// root of the document: the document DESCRIBES the image, the image is
// GENERATED_FROM the manifest, and the image CONTAINS every package the
// manifest contained. The manifest itself remains in the document as an
// ordinary package node.
//
// manifest must be the same bytes the SBOM was generated from. AddImage
// verifies this against the checksum recorded in the document and returns an
// error without modifying the document if they differ. An empty image.Name,
// or an image.SHA256 that is not a SHA-256 digest, is also rejected without
// modifying the document.
// creator is who and what is building the image. It may differ from the
// creator of the manifest, as when a later build reuses a manifest written
// by an earlier one.
func (s *SBOM) AddImage(image Image, manifest []byte, creator Creator) error {
	if image.Name == "" {
		return errors.New("image name is missing")
	}
	if creator.Tool.Name == "" {
		return errors.New("tool name is missing")
	}
	if creator.Tool.Version == "" {
		return errors.New("tool version is missing")
	}
	if err := validateSHA256(image.SHA256); err != nil {
		return err
	}

	nl := s.doc.NodeList

	// Get the root node of the SBOM
	roots := nl.GetRootNodes()
	// the manifest should have a singular root node
	if len(roots) != 1 {
		// TODO add a test that verifies this behavior
		return fmt.Errorf("SBOM has %d root nodes, expected exactly 1", len(roots))
	}
	rootNode := roots[0]

	// The root node of the SBOM is currently the manifest, ensure it is the same manifest passed in
	if len(manifest) == 0 {
		return errors.New("provided manifest is empty")
	}
	want := checksum(manifest)
	got := rootNode.Hashes[int32(pb.HashAlgorithm_SHA256)]
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("manifest sha256 mismatch: SBOM describes %q, provided manifest is %q", got, want)
	}

	edges := nl.GetEdgesFrom(rootNode.Id) // preserve the manifest's edges before adding new edges

	ns, err := documentNamespace(image.Name)
	if err != nil {
		return err
	}
	s.doc.Metadata.Name = image.Name
	s.doc.Metadata.Id = ns
	recordTool(s.doc, creator.Tool)
	recordOrganization(s.doc, creator.Organization)

	img := imageNode(image.Name, image.FileName, image.SHA256, creator.Organization)
	nl.RootElements = nil // turn the manifest into a normal node
	nl.AddRootNode(img)   // the image becomes the root node

	// the image is generated from the manifest
	// the From and To field order is confusing, read like so
	// `from  GENERATED_FROM to`
	// `image GENERATED_FROM manifest`
	nl.AddEdge(&pb.Edge{
		Type: pb.Edge_generatedFrom,
		From: img.Id,
		To:   []string{rootNode.Id},
	})

	// the manifest's CONTAINS edges describe the content that goes in the image, so we can
	// just copy them
	for _, e := range edges {
		if e.Type == pb.Edge_contains {
			nl.AddEdge(&pb.Edge{Type: pb.Edge_contains, From: img.Id, To: slices.Clone(e.To)})
		}
	}

	return nil
}

// recordTool appends tool when it is not already recorded. A later build with
// a different image-builder therefore appears alongside the one that wrote the
// manifest, and a rebuild with the same one does not add a duplicate.
//
// SPDX writes a tool as "name-version" and reads it back as that whole string
// in Name, with Version empty. Comparing the fields separately misses that
// tool, so the comparison is the serialized creator string, which does not
// require splitting a hyphenated name.
func recordTool(doc *pb.Document, tool ToolInfo) {
	want := spdxToolName(tool.Name, tool.Version)
	for _, recorded := range doc.Metadata.Tools {
		if spdxToolName(recorded.Name, recorded.Version) == want {
			return
		}
	}
	doc.Metadata.Tools = append(doc.Metadata.Tools, &pb.Tool{Name: tool.Name, Version: tool.Version})
}

// spdxToolName is the creator string SPDX records for a tool: name and version
// joined by a dash, or the name alone when there is no version.
func spdxToolName(name, version string) string {
	if version == "" {
		return name
	}
	return name + "-" + version
}

// recordOrganization appends an organization author. An empty name records
// nothing, and an organization already recorded is not recorded again.
func recordOrganization(doc *pb.Document, org string) {
	if org == "" {
		return
	}
	for _, recorded := range doc.Metadata.Authors {
		if recorded.IsOrg && recorded.Name == org {
			return
		}
	}
	doc.Metadata.Authors = append(doc.Metadata.Authors, &pb.Person{Name: org, IsOrg: true})
}

// documentNamespace is the SPDX namespace for a document:
// https://osbuild.org/spdxdocs/[DocumentName]-[UUID]. The UUID is random, so
// each document gets its own namespace.
func documentNamespace(name string) (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generating document namespace: %w", err)
	}
	return "https://osbuild.org/spdxdocs/" + name + "-" + id.String(), nil
}

// manifestNode builds the package node for the manifest. Its SPDX ID is derived
// from "manifest\n" plus the manifest's SHA-256, not from its name, so it stays
// distinct from an image the caller happens to name the same way.
func manifestNode(name, fileName, sha256, organization string) *pb.Node {
	return fileNode("manifest\n"+sha256, name, fileName, sha256, organization)
}

// imageNode builds the package node for the built image. Its SPDX ID is derived
// from "image\n" plus the image's SHA-256.
func imageNode(name, fileName, sha256, organization string) *pb.Node {
	return fileNode("image\n"+sha256, name, fileName, sha256, organization)
}

// fileNode builds a package node describing a single file artifact, such as
// the manifest or the disk image. idSeed is what the SPDX ID is derived from,
// and it is not the name the document shows.
func fileNode(idSeed, name, fileName, sha256, organization string) *pb.Node {
	node := &pb.Node{
		Id:       nodeId(idSeed),
		Type:     pb.Node_PACKAGE,
		Name:     name,
		FileName: fileName,
		Hashes: map[int32]string{
			int32(pb.HashAlgorithm_SHA256): sha256,
		},
	}
	if organization != "" {
		node.Suppliers = []*pb.Person{{Name: organization, IsOrg: true}}
	}
	return node
}

// nodeId derives a reproducible UUIDv5 identifier from v, so the same inputs
// always produce the same document IDs.
//
// TODO: Is that what we really want? Nice for testing/debug maybe but could it
// hurt anything?
func nodeId(v string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(v)).String()
}

// checksum returns the lowercase hex SHA-256 of content.
func checksum(content []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(content))
}

// validateSHA256 reports whether s is a SHA-256 digest: 64 lowercase hex characters.
func validateSHA256(s string) error {
	if s == "" {
		return errors.New("image sha256 is missing")
	}
	if len(s) != sha256.Size*2 {
		return fmt.Errorf("invalid image sha256 %q", s)
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("invalid image sha256 %q", s)
		}
	}
	return nil
}

// rpmNode builds a package node for an RPM package, identified by its purl.
func rpmNode(p rpmmd.Package) (*pb.Node, error) {
	purl := rpmPURL(p)
	hashes, err := packageHashes(p)
	if err != nil {
		return nil, err
	}
	node := &pb.Node{
		Id:       nodeId(purl),
		Type:     pb.Node_PACKAGE,
		Name:     p.Name,
		Version:  p.Version + "-" + p.Release,
		FileName: rpmFileName(p),
		UrlHome:  p.URL,
		Hashes:   hashes,
		Identifiers: map[int32]string{
			int32(pb.SoftwareIdentifierType_PURL): purl,
		},
	}
	if purlNamespace(p.Vendor) == "redhat" {
		node.Suppliers = []*pb.Person{{Name: "Red Hat", IsOrg: true}}
	}
	return node, nil
}

func packageHashes(p rpmmd.Package) (map[int32]string, error) {
	if p.Checksum.Value == "" {
		return nil, fmt.Errorf("package %s: missing checksum", p.Name)
	}
	if p.Checksum.Type == "" {
		return nil, fmt.Errorf("package %s: missing checksum type", p.Name)
	}
	algo, err := hashAlgorithm(p.Checksum.Type)
	if err != nil {
		return nil, fmt.Errorf("package %s: %w", p.Name, err)
	}
	return map[int32]string{int32(algo): p.Checksum.Value}, nil
}

// hashAlgorithm maps an RPM checksum type to the protobom enum.
// The set matches the digest curl will fetch: md5, sha1, sha256, sha384, sha512.
func hashAlgorithm(typ string) (pb.HashAlgorithm, error) {
	switch strings.ToLower(typ) {
	case "md5":
		return pb.HashAlgorithm_MD5, nil
	case "sha1":
		return pb.HashAlgorithm_SHA1, nil
	case "sha256":
		return pb.HashAlgorithm_SHA256, nil
	case "sha384":
		return pb.HashAlgorithm_SHA384, nil
	case "sha512":
		return pb.HashAlgorithm_SHA512, nil
	default:
		return pb.HashAlgorithm_UNKNOWN, fmt.Errorf("unsupported checksum type %q", typ)
	}
}

// rpmFileName is the on-disk RPM filename. Epoch is not part of it.
func rpmFileName(p rpmmd.Package) string {
	return fmt.Sprintf("%s-%s-%s.%s.rpm", p.Name, p.Version, p.Release, p.Arch)
}

// toProtobomFormat maps a Format to the corresponding protobom format.
func toProtobomFormat(f Format) (formats.Format, error) {
	switch f {
	case FormatSPDX23JSON:
		return formats.SPDX23JSON, nil
	case FormatCycloneDXJSON:
		return "", fmt.Errorf("unsupported SBOM format %q", f)
	default:
		return "", fmt.Errorf("unsupported SBOM format %q", f)
	}
}
