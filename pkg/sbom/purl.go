package sbom

import (
	"strconv"
	"strings"

	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/package-url/packageurl-go"
)

var vendorNamespaces = map[string]string{
	"red hat, inc.":                        "redhat",
	"fedora project":                       "fedora",
	"centos":                               "centos",
	"almalinux":                            "almalinux",
	"rocky enterprise software foundation": "rockylinux",
	"oracle america":                       "oraclelinux",
}

func purlNamespace(vendor string) string {
	v := strings.ToLower(vendor)
	if ns, ok := vendorNamespaces[v]; ok {
		return ns
	}
	return v
}

func rpmPURL(p rpmmd.Package) string {
	qualifiers := map[string]string{"arch": p.Arch}
	if p.Epoch != 0 {
		qualifiers["epoch"] = strconv.FormatUint(uint64(p.Epoch), 10)
	}
	if p.Repo != nil {
		if p.Repo.CanonicalID != "" {
			qualifiers["repository_id"] = p.Repo.CanonicalID
		}
		if location := rpmRepositoryURL(p.Repo); location != "" {
			qualifiers["repository_url"] = location
		}
	}
	return packageurl.NewPackageURL(
		packageurl.TypeRPM,
		purlNamespace(p.Vendor),
		p.Name,
		p.Version+"-"+p.Release,
		packageurl.QualifiersFromMap(qualifiers),
		"",
	).ToString()
}

func rpmRepositoryURL(repo *rpmmd.RepoConfig) string {
	for _, raw := range repo.BaseURLs {
		if location := metadataURL(raw); location != "" {
			return location
		}
	}
	if location := metadataURL(repo.Metalink); location != "" {
		return location
	}
	return metadataURL(repo.MirrorList)
}
