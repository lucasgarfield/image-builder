package sbom

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/osbuild/image-builder/pkg/container"
	"github.com/osbuild/image-builder/pkg/ostree"
	pb "github.com/protobom/protobom/pkg/sbom"
)

// homepageURL preserves project selectors (e.g. cgit's ?p=project.git).
// For authenticated or signed URLs use the stricter download URL policy.
func homepageURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" {
		return ""
	}
	u.Fragment = ""
	if u.User != nil {
		return metadataURL(raw)
	}
	// Inspect both query separators without rewriting the public homepage.
	q, err := url.ParseQuery(strings.ReplaceAll(u.RawQuery, ";", "&"))
	if err != nil {
		return metadataURL(raw)
	}
	for k := range q {
		key := strings.ToLower(k)
		switch key {
		case "sig", "key", "api_key", "apikey", "auth":
			return metadataURL(raw)
		}
		for _, sensitive := range []string{"token", "secret", "password", "signature", "credential", "x-amz-", "x-goog-"} {
			if strings.Contains(key, sensitive) {
				return metadataURL(raw)
			}
		}
	}
	return u.String()
}

// metadataURL retains public provenance, not credentials. Only carry known
// mirror-selection query fields; signed download URLs often include tokens.
func metadataURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" {
		return ""
	}
	u.User = nil
	u.Fragment = ""
	q := u.Query()
	for k := range q {
		switch k {
		case "repo", "arch", "releasever":
		default:
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	u.ForceQuery = false
	return u.String()
}

// sourceNode identifies resolved content even if the source did not expose a package inventory.
func sourceNode(kind, name, location, checksum string) (*pb.Node, error) {
	d, err := digest.Parse(checksum)
	if err != nil {
		return nil, fmt.Errorf("invalid %s digest %q: %w", kind, checksum, err)
	}
	algorithm, err := hashAlgorithm(string(d.Algorithm()))
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = checksum
	}
	return &pb.Node{
		Id:          nodeID(strings.Join([]string{kind, name, location, checksum}, "\n")),
		Type:        pb.Node_PACKAGE,
		Name:        name,
		Summary:     kind,
		Version:     checksum,
		UrlDownload: location,
		Hashes:      map[int32]string{int32(algorithm): d.Encoded()},
	}, nil
}

func containerNode(kind string, s container.Spec) (*pb.Node, error) {
	var location string
	if !s.LocalStorage && s.Source != "" {
		location = "docker://" + s.Source + "@" + s.Digest
	}
	name := s.LocalName
	if name == "" {
		name = s.Source
	}
	return sourceNode(kind, name, location, s.Digest)
}

func commitNode(kind string, s ostree.CommitSpec) (*pb.Node, error) {
	return sourceNode(kind, s.Ref, metadataURL(s.URL), "sha256:"+s.Checksum)
}

func (p Pipeline) nodes(pipeline string) ([]*pb.Node, error) {
	nodes, err := rpmNodes(pipeline, p.Packages)
	if err != nil {
		return nil, err
	}
	for _, s := range p.Containers {
		n, err := containerNode("container", s)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	for _, s := range p.Commits {
		n, err := commitNode("OSTree commit", s)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	for _, s := range p.Flatpaks {
		var n *pb.Node
		switch {
		case s.ContainerSpec != nil:
			n, err = containerNode("Flatpak container", *s.ContainerSpec)
		case s.CommitSpec != nil:
			n, err = commitNode("Flatpak commit", *s.CommitSpec)
		default:
			return nil, errors.New("unresolved Flatpak")
		}
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}
