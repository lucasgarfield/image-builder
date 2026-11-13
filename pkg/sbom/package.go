package sbom

import "github.com/osbuild/image-builder/pkg/rpmmd"

// Package is the subset of an RPM record an SBOM is built from.
//
// It deliberately omits repository configuration, credentials, client-certificate
// paths, and download URLs. Those ride along on rpmmd.Package and must not be
// copied into the RPM inventory persisted by task callers.
//
// Fields are exactly those Generate reads: NEVRA and vendor for the purl and
// filename, URL for the homepage, and the RPM file checksum.
type Package struct {
	Name    string
	Epoch   uint
	Version string
	Release string
	Arch    string
	Vendor  string
	URL     string

	Checksum rpmmd.Checksum
}

// PackageFromRPMMD copies only the fields an SBOM needs. Repo, Secrets,
// RemoteLocations, and the rest of the rpmmd record are dropped.
func PackageFromRPMMD(p rpmmd.Package) Package {
	return Package{
		Name:     p.Name,
		Epoch:    p.Epoch,
		Version:  p.Version,
		Release:  p.Release,
		Arch:     p.Arch,
		Vendor:   p.Vendor,
		URL:      p.URL,
		Checksum: p.Checksum,
	}
}
