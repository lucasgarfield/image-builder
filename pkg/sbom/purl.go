package sbom

import (
	"strconv"
	"strings"

	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/package-url/packageurl-go"
)

// vendorNamespaces maps lowercased package vendor names to the namespace used
// in their RPM purls.
var vendorNamespaces = map[string]string{
	"red hat, inc.":                        "redhat",
	"fedora project":                       "fedora",
	"centos":                               "centos",
	"almalinux":                            "almalinux",
	"rocky enterprise software foundation": "rockylinux",
	"oracle america":                       "oraclelinux",
}

// purlNamespace returns the purl namespace for a package vendor, falling back
// to the lowercased vendor name.
func purlNamespace(vendor string) string {
	v := strings.ToLower(vendor)
	if ns, ok := vendorNamespaces[v]; ok {
		return ns
	}
	return v
}

// rpmPURL returns the package-url for an RPM package.
func rpmPURL(p rpmmd.Package) string {
	qualifiers := map[string]string{"arch": p.Arch}
	// TODO: Add repository_id to qualifiers
	if p.Epoch != 0 {
		qualifiers["epoch"] = strconv.FormatUint(uint64(p.Epoch), 10)
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
