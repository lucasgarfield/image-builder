package sbom

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	pb "github.com/protobom/protobom/pkg/sbom"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func rpmID(pipeline, purl string) string { return nodeID("rpm\n" + pipeline + "\n" + purl) }

func rpmNodes(pipeline string, packages []rpmmd.Package) ([]*pb.Node, error) {
	nodes := make([]*pb.Node, 0, len(packages))
	seen := make(map[string]rpmmd.Checksum, len(packages))
	for _, p := range packages {
		node, err := rpmNode(pipeline, p)
		if err != nil {
			return nil, err
		}
		purl := node.Identifiers[int32(pb.SoftwareIdentifierType_PURL)]
		if recorded, ok := seen[purl]; ok {
			if recorded != p.Checksum {
				return nil, fmt.Errorf("duplicate package %q has checksum %s and %s", purl, recorded, p.Checksum)
			}
			continue
		}
		seen[purl] = p.Checksum
		nodes = append(nodes, node)
	}
	slices.SortFunc(nodes, func(a, b *pb.Node) int {
		return strings.Compare(
			a.Identifiers[int32(pb.SoftwareIdentifierType_PURL)],
			b.Identifiers[int32(pb.SoftwareIdentifierType_PURL)],
		)
	})
	return nodes, nil
}

func rpmNode(pipeline string, p rpmmd.Package) (*pb.Node, error) {
	for _, field := range []struct{ name, value string }{
		{"name", p.Name}, {"version", p.Version}, {"release", p.Release}, {"arch", p.Arch},
	} {
		if strings.TrimSpace(field.value) == "" {
			return nil, fmt.Errorf("package %q: missing %s", p.Name, field.name)
		}
	}
	purl := rpmPURL(p)
	hashes, err := packageHashes(p)
	if err != nil {
		return nil, err
	}
	license, licenseComments := rpmLicense(p.License)
	node := &pb.Node{
		Id:       rpmID(pipeline, purl),
		Type:     pb.Node_PACKAGE,
		Name:     p.Name,
		Version:  p.Version + "-" + p.Release,
		FileName: rpmFileName(p),
		UrlHome:  homepageURL(p.URL),
		Hashes:   hashes,
		Identifiers: map[int32]string{
			int32(pb.SoftwareIdentifierType_PURL): purl,
		},
		Licenses:        []string{license},
		LicenseComments: licenseComments,
	}
	if p.SourceRpm != "" {
		node.SourceInfo = "Source RPM: " + p.SourceRpm
	}
	if !p.BuildTime.IsZero() {
		node.BuildDate = timestamppb.New(p.BuildTime)
	}
	for _, loc := range p.RemoteLocations {
		location := metadataURL(loc)
		switch {
		case location == "" || location == node.UrlDownload:
		case node.UrlDownload == "":
			node.UrlDownload = location
		default:
			if !slices.ContainsFunc(node.ExternalReferences, func(ref *pb.ExternalReference) bool {
				return ref.Url == location
			}) {
				node.ExternalReferences = append(node.ExternalReferences, &pb.ExternalReference{
					Type: pb.ExternalReference_DOWNLOAD, Url: location, Comment: "Alternate RPM download location",
				})
			}
		}
	}
	if purlNamespace(p.Vendor) == "redhat" {
		node.Suppliers = []*pb.Person{{Name: "Red Hat", IsOrg: true}}
	}
	return node, nil
}

var licenseToken = regexp.MustCompile(`[[:alnum:].+:_-]+`)

func rpmLicense(raw string) (expression, comments string) {
	license := strings.TrimSpace(raw)
	if license == "" || license == "NOASSERTION" {
		return "NOASSERTION", ""
	}
	// Normalize operators before parsing; the validator canonicalizes license IDs.
	license = licenseToken.ReplaceAllStringFunc(license, func(token string) string {
		switch upper := strings.ToUpper(token); upper {
		case "AND", "OR", "WITH":
			return upper
		}
		return token
	})
	// SPDX references require extracted license texts or external documents
	// that the RPM license field does not provide.
	normalized, _ := spdxexp.ValidateAndNormalizeLicensesWithOptions([]string{license}, spdxexp.ValidateLicensesOptions{FailAllLicenseRefs: true, FailAllDocumentRefs: true})
	// The library applies ref options to atomic IDs only. Check compound expressions too.
	if len(normalized) == 1 && !strings.Contains(normalized[0], "LicenseRef-") && !strings.Contains(normalized[0], "DocumentRef-") {
		return normalized[0], ""
	}
	return "NOASSERTION", "RPM license is not a supported SPDX expression: " + raw
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
	size := map[pb.HashAlgorithm]int{
		pb.HashAlgorithm_MD5: 16, pb.HashAlgorithm_SHA1: 20,
		pb.HashAlgorithm_SHA256: 32, pb.HashAlgorithm_SHA384: 48, pb.HashAlgorithm_SHA512: 64,
	}[algo]
	digest, err := hex.DecodeString(p.Checksum.Value)
	if err != nil || len(digest) != size || p.Checksum.Value != strings.ToLower(p.Checksum.Value) {
		return nil, fmt.Errorf("package %s: invalid %s checksum %q", p.Name, p.Checksum.Type, p.Checksum.Value)
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
