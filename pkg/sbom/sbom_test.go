package sbom_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osbuild/image-builder/pkg/ostree"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	"github.com/osbuild/image-builder/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testInputs = sbom.Inputs{
	Creator: sbom.Creator{
		Tool: sbom.ToolInfo{
			Name:    "image-builder",
			Version: "1.2.3",
		},
	},
	Image: sbom.Image{
		Name:     "fedora-44-qcow2-x86_64",
		Version:  "1.5",
		FileName: "fedora-44-qcow2-x86_64.qcow2",
		SHA256:   "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752",
	},
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalRef struct {
	ReferenceType    string `json:"referenceType"`
	ReferenceLocator string `json:"referenceLocator"`
}

type spdxPackage struct {
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    *bool             `json:"filesAnalyzed"`
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	PackageFileName  string            `json:"packageFileName"`
	Supplier         string            `json:"supplier"`
	Homepage         string            `json:"homepage"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	LicenseComments  string            `json:"licenseComments"`
	LicenseConcluded string            `json:"licenseConcluded"`
	Copyright        string            `json:"copyrightText"`
	Purpose          string            `json:"primaryPackagePurpose"`
	SourceInfo       string            `json:"sourceInfo"`
	BuiltDate        string            `json:"builtDate"`
	Checksums        []spdxChecksum    `json:"checksums"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Related string `json:"relatedSpdxElement"`
	Type    string `json:"relationshipType"`
}

type spdxDoc struct {
	SPDXID            string `json:"SPDXID"`
	DataLicense       string `json:"dataLicense"`
	SPDXVersion       string `json:"spdxVersion"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Creators []string `json:"creators"`
		Created  string   `json:"created"`
	} `json:"creationInfo"`
	Packages      []spdxPackage      `json:"packages"`
	Relationships []spdxRelationship `json:"relationships"`
}

func writeSPDX(t *testing.T, s *sbom.Document) spdxDoc {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, s.Write(&buf, sbom.FormatSPDX23JSON))

	var out spdxDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	return out
}

func packageNamed(t *testing.T, doc spdxDoc, name string) spdxPackage {
	t.Helper()

	for _, p := range doc.Packages {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("package %q not in document", name)
	return spdxPackage{}
}

func assertDocumentNamespace(t *testing.T, name, namespace string) {
	t.Helper()
	prefix := "https://osbuild.org/spdxdocs/" + name + "-"
	require.True(t, strings.HasPrefix(namespace, prefix), "namespace %q", namespace)
	_, err := uuid.Parse(strings.TrimPrefix(namespace, prefix))
	require.NoError(t, err)
}

func bashRPM() rpmmd.Package {
	return rpmmd.Package{
		Name: "bash", Version: "5.2.26", Release: "3.fc40", Arch: "x86_64",
		Vendor: "Fedora Project", URL: "https://www.gnu.org/software/bash/",
		Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("a", 64)},
	}
}

func TestSPDXPipelineRelationships(t *testing.T) {
	in := testInputs
	in.Pipelines = map[string]sbom.Pipeline{
		"build": {}, "os": {}, "disk": {Inputs: []string{"os"}, BuildInputs: []string{"build"}},
	}
	doc, err := sbom.Generate(in)
	require.NoError(t, err)
	out := writeSPDX(t, doc)
	disk := packageNamed(t, out, "disk").SPDXID
	assert.ElementsMatch(t, []spdxRelationship{
		{out.SPDXID, "SPDXRef-Image", "DESCRIBES"},
		{"SPDXRef-Image", disk, "CONTAINS"},
		{disk, packageNamed(t, out, "os").SPDXID, "HAS_PREREQUISITE"},
		{packageNamed(t, out, "build").SPDXID, disk, "BUILD_TOOL_OF"},
	}, out.Relationships)
}

func TestSPDXImageRoot(t *testing.T) {
	for _, withPackages := range []bool{false, true} {
		t.Run(fmt.Sprintf("packages=%t", withPackages), func(t *testing.T) {
			in := testInputs
			if withPackages {
				other := bashRPM()
				other.Name = "coreutils"
				other.Requires = rpmmd.RelDepList{{Name: "bash", Relationship: ">=", Version: "5.2"}}
				in.Pipelines = map[string]sbom.Pipeline{
					"os":        {Packages: []rpmmd.Package{bashRPM(), other, bashRPM()}},
					"installer": {Packages: []rpmmd.Package{bashRPM()}},
				}
			}
			s, err := sbom.Generate(in)
			require.NoError(t, err)
			out := writeSPDX(t, s)
			assert.Equal(t, "SPDX-2.3", out.SPDXVersion)
			assert.Equal(t, "SPDXRef-DOCUMENT", out.SPDXID)
			assert.Equal(t, "CC0-1.0", out.DataLicense)
			_, err = time.Parse(time.RFC3339, out.CreationInfo.Created)
			require.NoError(t, err)
			seen := make(map[string]bool)
			for _, pkg := range out.Packages {
				assert.Regexp(t, `^SPDXRef-[a-zA-Z0-9.-]+$`, pkg.SPDXID)
				assert.False(t, seen[pkg.SPDXID], "duplicate SPDXID %s", pkg.SPDXID)
				seen[pkg.SPDXID] = true
				assert.NotEmpty(t, pkg.DownloadLocation)
				assert.Equal(t, "NOASSERTION", pkg.Copyright)
				assert.Equal(t, "NOASSERTION", pkg.LicenseConcluded)
				assert.Equal(t, "NOASSERTION", pkg.LicenseDeclared)
				require.NotNil(t, pkg.FilesAnalyzed)
				assert.False(t, *pkg.FilesAnalyzed)
			}
			assert.Equal(t, in.Image.Name, out.Name)
			image := packageNamed(t, out, in.Image.Name)
			assert.Equal(t, in.Image.FileName, image.PackageFileName)
			assert.Equal(t, "SPDXRef-Image", image.SPDXID)
			assert.Equal(t, "OPERATING-SYSTEM", image.Purpose)
			assert.Equal(t, "1.5", image.VersionInfo)
			assert.Contains(t, image.ExternalRefs, spdxExternalRef{"purl", "pkg:generic/fedora-44-qcow2-x86_64@1.5"})
			assert.Equal(t, []spdxChecksum{{"SHA256", in.Image.SHA256}}, image.Checksums)
			want := []spdxRelationship{{"SPDXRef-DOCUMENT", image.SPDXID, "DESCRIBES"}}
			if withPackages {
				os := packageNamed(t, out, "os")
				installer := packageNamed(t, out, "installer")
				var bash []spdxPackage
				for _, pkg := range out.Packages {
					if pkg.Name == "bash" {
						bash = append(bash, pkg)
					}
				}
				require.Len(t, bash, 2)
				// Pipelines are emitted in name order (installer, then os).
				assert.Equal(t, bash[0].ExternalRefs, bash[1].ExternalRefs)
				coreutils := packageNamed(t, out, "coreutils")
				want = append(want,
					spdxRelationship{image.SPDXID, os.SPDXID, "CONTAINS"},
					spdxRelationship{image.SPDXID, installer.SPDXID, "CONTAINS"},
					spdxRelationship{os.SPDXID, bash[1].SPDXID, "CONTAINS"},
					spdxRelationship{coreutils.SPDXID, bash[1].SPDXID, "DEPENDS_ON"},
					spdxRelationship{os.SPDXID, coreutils.SPDXID, "CONTAINS"},
					spdxRelationship{installer.SPDXID, bash[0].SPDXID, "CONTAINS"},
				)
				assert.Len(t, out.Packages, 6)
			} else {
				assert.Len(t, out.Packages, 1)
			}
			assert.ElementsMatch(t, want, out.Relationships)
		})
	}
}

func TestSPDXDocumentNamespaceAndCreators(t *testing.T) {
	for _, tt := range []struct{ name, escaped string }{
		{testInputs.Image.Name, testInputs.Image.Name},
		{"my image", "my%20image"}, {"100% image", "100%25%20image"},
		{"image#1", "image%231"}, {"café-image", "caf%C3%A9-image"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := testInputs
			in.Image.Name = tt.name
			for _, org := range []string{"", "Red Hat"} {
				in.Creator.Organization = org
				s, err := sbom.Generate(in)
				require.NoError(t, err)
				out := writeSPDX(t, s)
				assert.Equal(t, tt.name, out.Name)
				assertDocumentNamespace(t, tt.escaped, out.DocumentNamespace)
				creators := []string{"Tool: image-builder-1.2.3"}
				supplier := ""
				if org != "" {
					supplier = "Organization: " + org
					creators = append(creators, supplier)
				}
				assert.Subset(t, out.CreationInfo.Creators, creators)
				assert.Len(t, out.CreationInfo.Creators, len(creators)+1)
				image := packageNamed(t, out, tt.name)
				assert.Equal(t, supplier, image.Supplier)
				again, err := sbom.Generate(in)
				require.NoError(t, err)
				second := writeSPDX(t, again)
				assert.NotEqual(t, out.DocumentNamespace, second.DocumentNamespace)
				assert.Equal(t, image.SPDXID, packageNamed(t, second, tt.name).SPDXID)
			}
		})
	}
}

func TestSPDXRPMPackageFields(t *testing.T) {
	redhat := rpmmd.Package{
		Name: "openssl-libs", Epoch: 1, Version: "3.0.7", Release: "18.el9_2", Arch: "aarch64",
		Vendor: "Red Hat, Inc.", URL: "https://www.openssl.org/",
		Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("b", 64)},
	}
	for _, tt := range []struct {
		pkg                      rpmmd.Package
		filename, purl, supplier string
	}{
		{bashRPM(), "bash-5.2.26-3.fc40.x86_64.rpm", "pkg:rpm/fedora/bash@5.2.26-3.fc40?arch=x86_64", ""},
		{redhat, "openssl-libs-3.0.7-18.el9_2.aarch64.rpm", "pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=aarch64&epoch=1", "Organization: Red Hat"},
	} {
		t.Run(tt.pkg.Name, func(t *testing.T) {
			in := testInputs
			in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{tt.pkg}}}
			s, err := sbom.Generate(in)
			require.NoError(t, err)
			rpm := packageNamed(t, writeSPDX(t, s), tt.pkg.Name)
			assert.Equal(t, tt.filename, rpm.PackageFileName)
			assert.Equal(t, tt.supplier, rpm.Supplier)
			assert.Equal(t, tt.pkg.URL, rpm.Homepage)
			assert.Equal(t, "NOASSERTION", rpm.DownloadLocation)
			assert.Equal(t, tt.pkg.Version+"-"+tt.pkg.Release, rpm.VersionInfo)
			assert.Equal(t, []spdxChecksum{{"SHA256", tt.pkg.Checksum.Value}}, rpm.Checksums)
			assert.Contains(t, rpm.ExternalRefs, spdxExternalRef{"purl", tt.purl})
		})
	}
}

func TestSPDXRPMProvenance(t *testing.T) {
	p := bashRPM()
	p.SourceRpm = "bash-5.2.26-3.fc40.src.rpm"
	p.BuildTime = time.Date(2024, 10, 3, 11, 25, 0, 0, time.FixedZone("UTC+2", 2*60*60))
	p.RepoID = "internal-repo-key"
	p.Repo = &rpmmd.RepoConfig{
		Id: p.RepoID, CanonicalID: "fedora-40-updates",
		BaseURLs: []string{"https://repo.example.test/updates/40/"},
		Username: "secret-user", Password: "secret-password", SSLClientKey: "/path/to/client-key",
	}
	p.RemoteLocations = []string{
		"relative/path", "https://embedded-user:embedded-password@repo.example.test/updates/40/Packages/bash.rpm",
		"https://mirror.example.test/updates/40/Packages/bash.rpm", "https://mirror.example.test/updates/40/Packages/bash.rpm",
	}
	in := testInputs
	in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{p}}}
	s, err := sbom.Generate(in)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, s.Write(&buf, sbom.FormatSPDX23JSON))
	for _, private := range []string{"secret-user", "secret-password", "embedded-user", "embedded-password", "/path/to/client-key", p.RepoID} {
		assert.NotContains(t, buf.String(), private)
	}
	var out spdxDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	rpm := packageNamed(t, out, p.Name)
	assert.Equal(t, "https://repo.example.test/updates/40/Packages/bash.rpm", rpm.DownloadLocation)
	assert.Equal(t, "Source RPM: "+p.SourceRpm, rpm.SourceInfo)
	assert.Equal(t, "2024-10-03T09:25:00Z", rpm.BuiltDate)
	assert.ElementsMatch(t, []spdxExternalRef{
		{"purl", "pkg:rpm/fedora/bash@5.2.26-3.fc40?arch=x86_64&repository_id=fedora-40-updates&repository_url=https:%2F%2Frepo.example.test%2Fupdates%2F40%2F"},
		{"OTHER", "https://mirror.example.test/updates/40/Packages/bash.rpm"},
	}, rpm.ExternalRefs)
}

func TestProjectHomepagePreservesQuery(t *testing.T) {
	p := bashRPM()
	p.URL = "https://example.org/git?p=bash.git;a=summary" // legacy cgit URL uses semicolons
	in := testInputs
	in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{p}}}
	doc, err := sbom.Generate(in)
	require.NoError(t, err)
	assert.Equal(t, p.URL, packageNamed(t, writeSPDX(t, doc), p.Name).Homepage)
}

func TestSourceCredentialsAreNotPersisted(t *testing.T) {
	const location = "https://private-user:private-password@repo.example.test/repository?repo=fedora&token=private-token#private-fragment"
	p := bashRPM()
	p.URL = location
	p.Repo = &rpmmd.RepoConfig{BaseURLs: []string{location}}
	p.RemoteLocations = []string{location}
	in := testInputs
	in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{p}, Commits: []ostree.CommitSpec{{Ref: "test", URL: location, Checksum: strings.Repeat("a", 64)}}}}
	doc, err := sbom.Generate(in)
	require.NoError(t, err)
	var spdx, wire bytes.Buffer
	require.NoError(t, doc.Write(&spdx, sbom.FormatSPDX23JSON))
	require.NoError(t, doc.WriteProto(&wire))
	for _, data := range []string{spdx.String(), wire.String()} {
		assert.NotContains(t, data, "private-")
		assert.Contains(t, data, "repo.example.test/repository?repo=fedora")
	}
}

func TestSPDXRPMLicense(t *testing.T) {
	for _, tt := range []struct {
		name, license, declared string
		invalid                 bool
	}{
		{"canonical SPDX ID", "mit", "MIT", false},
		{"significant grouping", "(mit or Apache-2.0) and BSD-2-Clause", "(MIT OR Apache-2.0) AND BSD-2-Clause", false},
		{"compound expression", "MIT OR (Apache-2.0 AND GPL-2.0-only WITH Classpath-exception-2.0)", "MIT OR Apache-2.0 AND GPL-2.0-only WITH Classpath-exception-2.0", false},
		{"mixed-case operators and grouping", "MIT aNd (Apache-2.0 or GPL-2.0-only)", "MIT AND (Apache-2.0 OR GPL-2.0-only)", false},
		{"normalized exception", "GPL-2.0-only with Classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0", false},
		{"legacy RPM license", "MIT and GPLv2", "NOASSERTION", true},
		{"malformed expression", "(MIT OR Apache-2.0", "NOASSERTION", true},
		{"missing definition", "MIT AND LicenseRef-Fedora-Public-Domain", "NOASSERTION", true},
		{"empty RPM license", "", "NOASSERTION", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := bashRPM()
			p.License = tt.license
			in := testInputs
			in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{p}}}
			s, err := sbom.Generate(in)
			require.NoError(t, err)
			rpm := packageNamed(t, writeSPDX(t, s), p.Name)
			assert.Equal(t, tt.declared, rpm.LicenseDeclared)
			if tt.invalid {
				assert.Equal(t, "RPM license is not a supported SPDX expression: "+tt.license, rpm.LicenseComments)
			} else {
				assert.Empty(t, rpm.LicenseComments)
			}
		})
	}
}

func TestSPDXRPMChecksumAlgorithm(t *testing.T) {
	for _, tt := range []struct {
		typ    string
		length int
	}{
		{"md5", 32}, {"sha1", 40}, {"sha256", 64}, {"sha384", 96}, {"sha512", 128},
	} {
		t.Run(tt.typ, func(t *testing.T) {
			in := testInputs
			p := bashRPM()
			p.Checksum = rpmmd.Checksum{Type: tt.typ, Value: strings.Repeat("b", tt.length)}
			in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{p}}}
			s, err := sbom.Generate(in)
			require.NoError(t, err)
			rpm := packageNamed(t, writeSPDX(t, s), p.Name)
			assert.Equal(t, []spdxChecksum{{strings.ToUpper(tt.typ), p.Checksum.Value}}, rpm.Checksums)
		})
	}
}

func TestGenerateRejectsInvalidPackages(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*rpmmd.Package)
		want   string
	}{
		{"name", func(p *rpmmd.Package) { p.Name = "" }, "missing name"},
		{"blank name", func(p *rpmmd.Package) { p.Name = " \t" }, "missing name"},
		{"version", func(p *rpmmd.Package) { p.Version = "" }, "missing version"},
		{"release", func(p *rpmmd.Package) { p.Release = "" }, "missing release"},
		{"arch", func(p *rpmmd.Package) { p.Arch = "" }, "missing arch"},
		{"checksum", func(p *rpmmd.Package) { p.Checksum.Value = "" }, "missing checksum"},
		{"type", func(p *rpmmd.Package) { p.Checksum.Type = "" }, "missing checksum type"},
		{"unsupported", func(p *rpmmd.Package) { p.Checksum.Type = "sha224" }, `unsupported checksum type "sha224"`},
		{"short", func(p *rpmmd.Package) { p.Checksum.Value = "aa" }, "invalid sha256 checksum"},
		{"long", func(p *rpmmd.Package) { p.Checksum.Value += "aa" }, "invalid sha256 checksum"},
		{"not hex", func(p *rpmmd.Package) { p.Checksum.Value = strings.Repeat("z", 64) }, "invalid sha256 checksum"},
		{"uppercase", func(p *rpmmd.Package) { p.Checksum.Value = strings.Repeat("A", 64) }, "invalid sha256 checksum"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := bashRPM()
			tt.change(&p)
			in := testInputs
			in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{p}}}
			s, err := sbom.Generate(in)
			assert.ErrorContains(t, err, tt.want)
			assert.Nil(t, s)
		})
	}
	in := testInputs
	in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{bashRPM(), bashRPM()}}}
	_, err := sbom.Generate(in)
	require.NoError(t, err)
	conflict := bashRPM()
	conflict.Checksum.Value = strings.Repeat("b", 64)
	in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: []rpmmd.Package{bashRPM(), conflict}}}
	const want = `duplicate package "pkg:rpm/fedora/bash@5.2.26-3.fc40?arch=x86_64"`
	s, err := sbom.Generate(in)
	assert.ErrorContains(t, err, want)
	assert.Nil(t, s)
}

func TestSPDXImageChecksumOptional(t *testing.T) {
	in := testInputs
	in.Image.SHA256 = ""
	s, err := sbom.Generate(in)
	require.NoError(t, err)
	assert.Empty(t, packageNamed(t, writeSPDX(t, s), in.Image.Name).Checksums)
}

func TestGenerateInvalidInputs(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*sbom.Inputs)
		want   string
	}{
		{"image name", func(in *sbom.Inputs) { in.Image.Name = "" }, "image name is missing"},
		{"tool name", func(in *sbom.Inputs) { in.Creator.Tool.Name = "" }, "tool name is missing"},
		{"tool version", func(in *sbom.Inputs) { in.Creator.Tool.Version = "" }, "tool version is missing"},
		{"short digest", func(in *sbom.Inputs) { in.Image.SHA256 = "aa" }, "invalid image sha256"},
		{"uppercase digest", func(in *sbom.Inputs) { in.Image.SHA256 = strings.Repeat("A", 64) }, "invalid image sha256"},
		{"nonhex digest", func(in *sbom.Inputs) { in.Image.SHA256 = strings.Repeat("z", 64) }, "invalid image sha256"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := testInputs
			tt.change(&in)
			s, err := sbom.Generate(in)
			assert.ErrorContains(t, err, tt.want)
			assert.Nil(t, s)
		})
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDocumentWriteErrors(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)
	var buf bytes.Buffer
	assert.ErrorContains(t, s.Write(&buf, "foo"), `unsupported SBOM format "foo"`)
	assert.Zero(t, buf.Len())
	writeErr := errors.New("writer failed")
	assert.ErrorIs(t, s.Write(errorWriter{writeErr}, sbom.FormatSPDX23JSON), writeErr)
}

func TestSPDXPackagesSortedByPURL(t *testing.T) {
	for _, tt := range []struct {
		name     string
		packages []rpmmd.Package
		purls    []string
	}{
		{
			name: "unsorted input",
			packages: []rpmmd.Package{
				{
					Name:    "openssl-libs",
					Epoch:   1,
					Version: "3.0.7",
					Release: "18.el9_2",
					Arch:    "aarch64",
					Vendor:  "Red Hat, Inc.",
					URL:     "https://www.openssl.org/",
					Checksum: rpmmd.Checksum{
						Type:  "sha256",
						Value: strings.Repeat("b", 64),
					},
				},
				{
					Name:    "bash",
					Version: "5.2.26",
					Release: "3.fc40",
					Arch:    "x86_64",
					Vendor:  "Fedora Project",
					URL:     "https://www.gnu.org/software/bash/",
					Checksum: rpmmd.Checksum{
						Type:  "sha256",
						Value: strings.Repeat("a", 64),
					},
				},
				{
					Name:    "zsh",
					Version: "1.0",
					Release: "1.al8",
					Arch:    "x86_64",
					Vendor:  "AlmaLinux",
					URL:     "https://example.test/zsh",
					Checksum: rpmmd.Checksum{
						Type:  "sha256",
						Value: strings.Repeat("c", 64),
					},
				},
			},
			purls: []string{
				"pkg:rpm/almalinux/zsh@1.0-1.al8?arch=x86_64",
				"pkg:rpm/fedora/bash@5.2.26-3.fc40?arch=x86_64",
				"pkg:rpm/redhat/openssl-libs@3.0.7-18.el9_2?arch=aarch64&epoch=1",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := testInputs
			in.Pipelines = map[string]sbom.Pipeline{"os": {Packages: tt.packages}}
			s, err := sbom.Generate(in)
			require.NoError(t, err)
			var got []string
			for _, pkg := range writeSPDX(t, s).Packages {
				for _, ref := range pkg.ExternalRefs {
					if ref.ReferenceType == "purl" && strings.HasPrefix(ref.ReferenceLocator, "pkg:rpm/") {
						got = append(got, ref.ReferenceLocator)
					}
				}
			}
			assert.Equal(t, tt.purls, got)
		})
	}
}
