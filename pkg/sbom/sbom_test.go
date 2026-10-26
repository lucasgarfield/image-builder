package sbom_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
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
	Name:     "fedora-44-qcow2-x86_64-manifest",
	FileName: "fedora-44-qcow2-x86_64.osbuild-manifest.json",
	Manifest: []byte(`{
    "version": "2",
    "pipelines": [],
    "sources": {}
}
`),
}

var testImage = sbom.Image{
	Name:     "fedora-44-qcow2-x86_64",
	FileName: "fedora-44-qcow2-x86_64.qcow2",
	SHA256:   "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752",
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
	SPDXID          string            `json:"SPDXID"`
	Name            string            `json:"name"`
	VersionInfo     string            `json:"versionInfo"`
	PackageFileName string            `json:"packageFileName"`
	Supplier        string            `json:"supplier"`
	Homepage        string            `json:"homepage"`
	Checksums       []spdxChecksum    `json:"checksums"`
	ExternalRefs    []spdxExternalRef `json:"externalRefs"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Related string `json:"relatedSpdxElement"`
	Type    string `json:"relationshipType"`
}

type spdxDoc struct {
	SPDXVersion       string `json:"spdxVersion"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages      []spdxPackage      `json:"packages"`
	Relationships []spdxRelationship `json:"relationships"`
}

func writeSPDX(t *testing.T, s *sbom.SBOM) spdxDoc {
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

// assertDocumentNamespace checks the SPDX form
// https://osbuild.org/spdxdocs/[name]-[UUID]. The UUID is random, so the
// value itself is not compared.
func assertDocumentNamespace(t *testing.T, name, namespace string) {
	t.Helper()
	prefix := "https://osbuild.org/spdxdocs/" + name + "-"
	require.True(t, strings.HasPrefix(namespace, prefix), "namespace %q", namespace)
	_, err := uuid.Parse(strings.TrimPrefix(namespace, prefix))
	require.NoError(t, err)
}

func packageByFileName(t *testing.T, doc spdxDoc, fileName string) spdxPackage {
	t.Helper()
	for _, p := range doc.Packages {
		if p.PackageFileName == fileName {
			return p
		}
	}
	t.Fatalf("package file %q not in document", fileName)
	return spdxPackage{}
}

// The caller supplies the manifest package name and the file name it will be
// written as. Neither is invented here. The same name is the SPDX document name.
func TestSPDXManifestNameAndFileName(t *testing.T) {
	in := testInputs
	in.Name = "centos-9-qcow2-x86_64-manifest"
	in.FileName = "centos-9-qcow2-x86_64.osbuild-manifest.json"

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	out := writeSPDX(t, s)
	assert.Equal(t, in.Name, out.Name)
	manifest := packageNamed(t, out, in.Name)
	assert.Equal(t, in.FileName, manifest.PackageFileName)
}

// In the SPDX relationships list, the DOCUMENT DESCRIBES relationship should
// be to the manifest when an SBOM is produced via `image-builder manifest`.
// The first package in the packages list is the manifest.
func TestSPDXDocumentDescribesManifest(t *testing.T) {
	in := testInputs

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	out := writeSPDX(t, s)

	manifest := packageNamed(t, out, testInputs.Name)
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: fmt.Sprintf("%x", sha256.Sum256(testInputs.Manifest)),
	}}, manifest.Checksums)
	assert.Equal(t, []spdxRelationship{
		{Element: "SPDXRef-DOCUMENT", Related: manifest.SPDXID, Type: "DESCRIBES"},
	}, out.Relationships)
}

func TestSPDXManifestContainsPackages(t *testing.T) {
	in := testInputs
	in.Packages = rpmmd.PackageList{
		{
			Name:     "bash",
			Version:  "5.2.26",
			Release:  "3.fc40",
			Arch:     "x86_64",
			Vendor:   "Fedora",
			Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("a", 64)},
		},
		{
			Name:     "libstdc++",
			Version:  "14.2.1",
			Release:  "3.fc41",
			Arch:     "x86_64",
			Vendor:   "Fedora Project",
			Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("c", 64)},
		},
	}

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	out := writeSPDX(t, s)

	require.Len(t, out.Packages, 3)
	manifest := packageNamed(t, out, testInputs.Name)
	bash := packageNamed(t, out, "bash")
	libstdcpp := packageNamed(t, out, "libstdc++")

	assert.Equal(t, "5.2.26-3.fc40", bash.VersionInfo)
	assert.Contains(t, bash.ExternalRefs, spdxExternalRef{
		ReferenceType:    "purl",
		ReferenceLocator: "pkg:rpm/fedora/bash@5.2.26-3.fc40?arch=x86_64",
	})

	assert.Equal(t, "libstdc++", libstdcpp.Name)
	assert.Equal(t, "14.2.1-3.fc41", libstdcpp.VersionInfo)
	assert.Contains(t, libstdcpp.ExternalRefs, spdxExternalRef{
		ReferenceType:    "purl",
		ReferenceLocator: "pkg:rpm/fedora/libstdc%2B%2B@14.2.1-3.fc41?arch=x86_64",
	})

	assert.ElementsMatch(t, []spdxRelationship{
		{Element: "SPDXRef-DOCUMENT", Related: manifest.SPDXID, Type: "DESCRIBES"},
		{Element: manifest.SPDXID, Related: bash.SPDXID, Type: "CONTAINS"},
		{Element: manifest.SPDXID, Related: libstdcpp.SPDXID, Type: "CONTAINS"},
	}, out.Relationships)
}

// The namespace UUID is a UUIDv5 of the artifact SHA-256 and the image-builder
// version that produced it, joined by a newline. The version used for the image
// is the one passed to AddImage, which may not be the one that wrote the manifest.
func TestSPDXDocumentNamespace(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	out := writeSPDX(t, s)
	assertDocumentNamespace(t, testInputs.Name, out.DocumentNamespace)
	assert.Equal(t, []string{"Tool: protobom-devel", "Tool: image-builder-1.2.3"}, out.CreationInfo.Creators)

	again, err := sbom.Generate(testInputs)
	require.NoError(t, err)
	assert.NotEqual(t, out.DocumentNamespace, writeSPDX(t, again).DocumentNamespace)

	require.NoError(t, s.AddImage(testImage, testInputs.Manifest, sbom.Creator{Tool: sbom.ToolInfo{Name: "image-builder", Version: "2.3.4"}}))

	out = writeSPDX(t, s)
	assertDocumentNamespace(t, testImage.Name, out.DocumentNamespace)
	assert.Equal(t, []string{
		"Tool: protobom-devel",
		"Tool: image-builder-1.2.3",
		"Tool: image-builder-2.3.4",
	}, out.CreationInfo.Creators)
}

// Updating the document creates a new document, so AddImage must mint a new
// namespace. The image has the manifest's name, so rewriting the name cannot
// pass this by itself: the URI has to change.
func TestAddImageMintsNewNamespace(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)
	before := writeSPDX(t, s).DocumentNamespace

	img := testImage
	img.Name = testInputs.Name
	require.NoError(t, s.AddImage(img, testInputs.Manifest, testInputs.Creator))

	after := writeSPDX(t, s).DocumentNamespace
	assertDocumentNamespace(t, img.Name, after)
	assert.NotEqual(t, before, after)
}

// An organization is recorded after the tools. It is not part of the namespace.
func TestSPDXOrganizationCreator(t *testing.T) {
	in := testInputs
	in.Creator.Organization = "Red Hat"

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	out := writeSPDX(t, s)
	assertDocumentNamespace(t, in.Name, out.DocumentNamespace)
	assert.Equal(t, []string{
		"Tool: protobom-devel",
		"Tool: image-builder-1.2.3",
		"Organization: Red Hat",
	}, out.CreationInfo.Creators)
	assert.Equal(t, "Organization: Red Hat", packageNamed(t, out, in.Name).Supplier)
}

func TestWriteSPDX(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	out := writeSPDX(t, s)
	assert.Equal(t, "SPDX-2.3", out.SPDXVersion)
	assert.Contains(t, out.CreationInfo.Creators, "Tool: image-builder-1.2.3")
}

func TestWriteUnknownFormat(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = s.Write(&buf, sbom.Format("foo"))
	assert.ErrorContains(t, err, `unsupported SBOM format "foo"`)
	assert.Zero(t, buf.Len())
}

func TestGenerateRejectsEmptyManifest(t *testing.T) {
	in := testInputs
	in.Manifest = nil

	s, err := sbom.Generate(in)
	assert.ErrorContains(t, err, "manifest is empty")
	assert.Nil(t, s)
}

func TestGenerateRejectsEmptyName(t *testing.T) {
	in := testInputs
	in.Name = ""

	s, err := sbom.Generate(in)
	assert.ErrorContains(t, err, "manifest name is missing")
	assert.Nil(t, s)
}

func TestGenerateRejectsEmptyToolName(t *testing.T) {
	in := testInputs
	in.Creator.Tool.Name = ""

	s, err := sbom.Generate(in)
	assert.ErrorContains(t, err, "tool name is missing")
	assert.Nil(t, s)
}

func TestGenerateRejectsEmptyVersion(t *testing.T) {
	in := testInputs
	in.Creator.Tool.Version = ""

	s, err := sbom.Generate(in)
	assert.ErrorContains(t, err, "tool version is missing")
	assert.Nil(t, s)
}

// A Red Hat binary RPM records the on-disk filename, the SHA-256 of the RPM
// file, the RPM URL, and Red Hat as the supplying organization.
func TestSPDXRedHatRPMPackageFields(t *testing.T) {
	in := testInputs
	in.Packages = rpmmd.PackageList{{
		Name:    "openssl-libs",
		Epoch:   1,
		Version: "3.0.7",
		Release: "18.el9_2",
		Arch:    "aarch64",
		Vendor:  "Red Hat, Inc.",
		URL:     "https://www.openssl.org/",
		// Checksum is the digest of the whole RPM file, the pkgid dnf checks
		// after download. Signing the package rewrites the signature header, so
		// this value changes. It is the checksum the SBOM records.
		Checksum: rpmmd.Checksum{Type: "sha256", Value: "cae5941219fd64e75c2b29509c6fe712bef77181a586702275a46a5e812d4dd4"},
		// HeaderChecksum is the digest of the RPM header alone, not the signature
		// and not the payload, so it survives signing. It is a different artifact
		// and must not be reported as the package checksum.
		HeaderChecksum: rpmmd.Checksum{Type: "sha256", Value: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}}

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	out := writeSPDX(t, s)
	rpm := packageNamed(t, out, "openssl-libs")

	assert.Equal(t, "openssl-libs-3.0.7-18.el9_2.aarch64.rpm", rpm.PackageFileName)
	assert.Equal(t, "Organization: Red Hat", rpm.Supplier)
	assert.Equal(t, "https://www.openssl.org/", rpm.Homepage)
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: "cae5941219fd64e75c2b29509c6fe712bef77181a586702275a46a5e812d4dd4",
	}}, rpm.Checksums)
}

// A Fedora package records the same file fields, but not a Red Hat supplier.
func TestSPDXFedoraRPMPackageFields(t *testing.T) {
	in := testInputs
	in.Packages = rpmmd.PackageList{{
		Name:     "bash",
		Version:  "5.2.26",
		Release:  "3.fc40",
		Arch:     "x86_64",
		Vendor:   "Fedora Project",
		URL:      "https://www.gnu.org/software/bash/",
		Checksum: rpmmd.Checksum{Type: "sha256", Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}}

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	out := writeSPDX(t, s)
	rpm := packageNamed(t, out, "bash")

	assert.Equal(t, "bash-5.2.26-3.fc40.x86_64.rpm", rpm.PackageFileName)
	assert.Empty(t, rpm.Supplier)
	assert.Equal(t, "https://www.gnu.org/software/bash/", rpm.Homepage)
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}, rpm.Checksums)
}

// rpmNode must record the checksum under the algorithm rpmmd actually used.
// The accepted types are the ones curl will fetch: md5, sha1, sha256, sha384,
// and sha512.
func TestSPDXRPMChecksumAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		rpmmdType string
		digest    string
		wantAlgo  string
	}{
		{
			name:      "md5",
			rpmmdType: "md5",
			digest:    strings.Repeat("b", 32),
			wantAlgo:  "MD5",
		},
		{
			name:      "sha1",
			rpmmdType: "sha1",
			digest:    strings.Repeat("b", 40),
			wantAlgo:  "SHA1",
		},
		{
			name:      "sha256",
			rpmmdType: "sha256",
			digest:    strings.Repeat("b", 64),
			wantAlgo:  "SHA256",
		},
		{
			name:      "sha384",
			rpmmdType: "sha384",
			digest:    strings.Repeat("b", 96),
			wantAlgo:  "SHA384",
		},
		{
			name:      "sha512",
			rpmmdType: "sha512",
			digest:    strings.Repeat("b", 128),
			wantAlgo:  "SHA512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := testInputs
			in.Packages = rpmmd.PackageList{{
				Name:     "bash",
				Version:  "5.2.26",
				Release:  "3.fc40",
				Arch:     "x86_64",
				Checksum: rpmmd.Checksum{Type: tt.rpmmdType, Value: tt.digest},
			}}

			s, err := sbom.Generate(in)
			require.NoError(t, err)

			rpm := packageNamed(t, writeSPDX(t, s), "bash")
			assert.Equal(t, []spdxChecksum{{
				Algorithm:     tt.wantAlgo,
				ChecksumValue: tt.digest,
			}}, rpm.Checksums)
		})
	}
}

// A checksum curl would refuse to fetch, or one that is incomplete, must not
// be recorded under some other algorithm.
func TestSPDXRPMChecksumRejected(t *testing.T) {
	tests := []struct {
		name      string
		rpmmdType string
		digest    string
		wantErr   string
	}{
		{
			name:      "sha alias",
			rpmmdType: "sha",
			digest:    strings.Repeat("b", 40),
			wantErr:   `unsupported checksum type "sha"`,
		},
		{
			name:      "sha224",
			rpmmdType: "sha224",
			digest:    strings.Repeat("b", 56),
			wantErr:   `unsupported checksum type "sha224"`,
		},
		{
			name:      "blake3",
			rpmmdType: "blake3",
			digest:    strings.Repeat("b", 64),
			wantErr:   `unsupported checksum type "blake3"`,
		},
		{
			name:    "no checksum",
			wantErr: "missing checksum",
		},
		{
			name:      "sha256 without a digest",
			rpmmdType: "sha256",
			wantErr:   "missing checksum",
		},
		{
			name:    "digest without a type",
			digest:  strings.Repeat("b", 64),
			wantErr: "missing checksum type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := testInputs
			in.Packages = rpmmd.PackageList{{
				Name:     "bash",
				Version:  "5.2.26",
				Release:  "3.fc40",
				Arch:     "x86_64",
				Checksum: rpmmd.Checksum{Type: tt.rpmmdType, Value: tt.digest},
			}}

			s, err := sbom.Generate(in)
			require.ErrorContains(t, err, tt.wantErr)
			assert.Nil(t, s)
		})
	}
}

func bashRPM(digest string) rpmmd.Package {
	return rpmmd.Package{
		Name:     "bash",
		Version:  "5.2.26",
		Release:  "3.fc40",
		Arch:     "x86_64",
		Vendor:   "Fedora Project",
		Checksum: rpmmd.Checksum{Type: "sha256", Value: digest},
	}
}

// Merged package lists can name an RPM twice. An exact duplicate, the same purl
// and the same checksum, is recorded once. A second copy with a different
// checksum is a conflict, since a purl does not include the checksum.
func TestGenerateDeduplicatesIdenticalRPMs(t *testing.T) {
	digest := strings.Repeat("a", 64)
	in := testInputs
	in.Packages = rpmmd.PackageList{bashRPM(digest), bashRPM(digest), bashRPM(digest)}

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	out := writeSPDX(t, s)
	manifest := packageNamed(t, out, in.Name)
	bash := packageNamed(t, out, "bash")
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: digest,
	}}, bash.Checksums)
	assert.ElementsMatch(t, []spdxRelationship{
		{Element: "SPDXRef-DOCUMENT", Related: manifest.SPDXID, Type: "DESCRIBES"},
		{Element: manifest.SPDXID, Related: bash.SPDXID, Type: "CONTAINS"},
	}, out.Relationships)
}

func TestGenerateRejectsRPMChecksumConflict(t *testing.T) {
	in := testInputs
	in.Packages = rpmmd.PackageList{
		bashRPM(strings.Repeat("a", 64)),
		bashRPM(strings.Repeat("b", 64)),
	}

	s, err := sbom.Generate(in)
	assert.ErrorContains(t, err, `duplicate package "pkg:rpm/fedora/bash@5.2.26-3.fc40?arch=x86_64"`)
	assert.ErrorContains(t, err, strings.Repeat("a", 64))
	assert.ErrorContains(t, err, strings.Repeat("b", 64))
	assert.Nil(t, s)
}

func TestReadSPDXRoundTrip(t *testing.T) {
	in := testInputs
	in.Packages = rpmmd.PackageList{
		{
			Name:     "bash",
			Version:  "5.2.26",
			Release:  "3.fc40",
			Arch:     "x86_64",
			Vendor:   "Fedora",
			Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("a", 64)},
		},
	}

	orig, err := sbom.Generate(in)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, orig.Write(&buf, sbom.FormatSPDX23JSON))

	got, err := sbom.Read(&buf, sbom.FormatSPDX23JSON)
	require.NoError(t, err)

	assert.Equal(t, writeSPDX(t, orig), writeSPDX(t, got))
}

func roundTrip(t *testing.T, s *sbom.SBOM) *sbom.SBOM {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, s.Write(&buf, sbom.FormatSPDX23JSON))
	loaded, err := sbom.Read(&buf, sbom.FormatSPDX23JSON)
	require.NoError(t, err)
	return loaded
}

// The document a caller keeps is the one they wrote and read back, not the one
// Generate returned. Generate, write, and read produces a manifest document.
// AddImage, write, and read turns it into an image document. The image is the
// only described root, both checksums survive, and the same tool is not
// recorded twice.
func TestSPDXLifecycle(t *testing.T) {
	in := testInputs
	in.Creator.Organization = "Red Hat"
	in.Packages = rpmmd.PackageList{{
		Name:     "bash",
		Version:  "5.2.26",
		Release:  "3.fc40",
		Arch:     "x86_64",
		Vendor:   "Fedora Project",
		Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("a", 64)},
	}}

	s, err := sbom.Generate(in)
	require.NoError(t, err)
	s = roundTrip(t, s)

	out := writeSPDX(t, s)
	manifest := packageNamed(t, out, in.Name)
	bash := packageNamed(t, out, "bash")
	assertDocumentNamespace(t, in.Name, out.DocumentNamespace)
	assert.Equal(t, in.Name, out.Name)
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: fmt.Sprintf("%x", sha256.Sum256(in.Manifest)),
	}}, manifest.Checksums)
	assert.Equal(t, "Organization: Red Hat", manifest.Supplier)
	assert.Equal(t, []string{
		"Tool: protobom-devel",
		"Tool: image-builder-1.2.3",
		"Organization: Red Hat",
	}, out.CreationInfo.Creators)
	assert.ElementsMatch(t, []spdxRelationship{
		{Element: "SPDXRef-DOCUMENT", Related: manifest.SPDXID, Type: "DESCRIBES"},
		{Element: manifest.SPDXID, Related: bash.SPDXID, Type: "CONTAINS"},
	}, out.Relationships)

	require.NoError(t, s.AddImage(testImage, in.Manifest, in.Creator))
	s = roundTrip(t, s)

	out = writeSPDX(t, s)
	manifest = packageNamed(t, out, in.Name)
	image := packageNamed(t, out, testImage.Name)
	bash = packageNamed(t, out, "bash")
	assertDocumentNamespace(t, testImage.Name, out.DocumentNamespace)
	assert.Equal(t, testImage.Name, out.Name)
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: testImage.SHA256,
	}}, image.Checksums)
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: fmt.Sprintf("%x", sha256.Sum256(in.Manifest)),
	}}, manifest.Checksums)
	assert.Equal(t, "Organization: Red Hat", image.Supplier)
	assert.Equal(t, "Organization: Red Hat", manifest.Supplier)
	assert.Equal(t, []string{
		"Tool: protobom-devel",
		"Tool: image-builder-1.2.3",
		"Organization: Red Hat",
	}, out.CreationInfo.Creators)
	assert.ElementsMatch(t, []spdxRelationship{
		{Element: image.SPDXID, Related: manifest.SPDXID, Type: "GENERATED_FROM"},
		{Element: "SPDXRef-DOCUMENT", Related: image.SPDXID, Type: "DESCRIBES"},
		{Element: manifest.SPDXID, Related: bash.SPDXID, Type: "CONTAINS"},
		{Element: image.SPDXID, Related: bash.SPDXID, Type: "CONTAINS"},
	}, out.Relationships)
}

func TestReadUnknownFormat(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, s.Write(&buf, sbom.FormatSPDX23JSON))

	got, err := sbom.Read(&buf, sbom.Format("foo"))
	assert.ErrorContains(t, err, `unsupported SBOM format "foo"`)
	assert.Nil(t, got)
}

// AddImage records the image under the name and file name the caller supplies,
// and makes that name the SPDX document name. The manifest's own name and file
// name stay in place.
func TestSPDXImageNameAndFileName(t *testing.T) {
	in := testInputs
	in.Name = "centos-9-qcow2-x86_64-manifest"
	in.FileName = "centos-9-qcow2-x86_64.osbuild-manifest.json"

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	img := sbom.Image{
		Name:     "centos-9-qcow2-x86_64",
		FileName: "centos-9-qcow2-x86_64.qcow2",
		SHA256:   testImage.SHA256,
	}
	require.NoError(t, s.AddImage(img, in.Manifest, testInputs.Creator))

	out := writeSPDX(t, s)
	assert.Equal(t, img.Name, out.Name)
	assert.Equal(t, img.FileName, packageNamed(t, out, img.Name).PackageFileName)
	assert.Equal(t, in.FileName, packageNamed(t, out, in.Name).PackageFileName)
}

func TestAddImageDescribesImages(t *testing.T) {
	in := testInputs
	in.Packages = rpmmd.PackageList{
		{
			Name:     "bash",
			Version:  "5.2.26",
			Release:  "3.fc40",
			Arch:     "x86_64",
			Vendor:   "Fedora Project",
			Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("a", 64)},
		},
		{
			Name:     "libstdc++",
			Version:  "14.2.1",
			Release:  "3.fc41",
			Arch:     "x86_64",
			Vendor:   "Fedora Project",
			Checksum: rpmmd.Checksum{Type: "sha256", Value: strings.Repeat("c", 64)},
		},
	}

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	err = s.AddImage(testImage, in.Manifest, testInputs.Creator)
	require.NoError(t, err)

	out := writeSPDX(t, s)

	manifest := packageNamed(t, out, testInputs.Name)
	bash := packageNamed(t, out, "bash")
	libstdcpp := packageNamed(t, out, "libstdc++")
	image := packageNamed(t, out, testImage.Name)

	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: testImage.SHA256,
	}}, image.Checksums)

	assert.ElementsMatch(t, []spdxRelationship{
		{Element: "SPDXRef-DOCUMENT", Related: image.SPDXID, Type: "DESCRIBES"},
		{Element: image.SPDXID, Related: manifest.SPDXID, Type: "GENERATED_FROM"},
		{Element: manifest.SPDXID, Related: bash.SPDXID, Type: "CONTAINS"},
		{Element: manifest.SPDXID, Related: libstdcpp.SPDXID, Type: "CONTAINS"},
		{Element: image.SPDXID, Related: bash.SPDXID, Type: "CONTAINS"},
		{Element: image.SPDXID, Related: libstdcpp.SPDXID, Type: "CONTAINS"},
	}, out.Relationships)
}

// The image and the manifest are different artifacts, so their SPDX IDs come
// from "manifest\n" or "image\n" plus the artifact's SHA-256, not from the name.
// A caller can give both the same name and a write/read round trip still has
// both, each with its own checksum, and the image GENERATED_FROM the manifest.
func TestAddImageSameNameAsManifest(t *testing.T) {
	in := testInputs

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	img := testImage
	img.Name = in.Name
	require.NoError(t, s.AddImage(img, in.Manifest, in.Creator))

	var buf bytes.Buffer
	require.NoError(t, s.Write(&buf, sbom.FormatSPDX23JSON))
	loaded, err := sbom.Read(&buf, sbom.FormatSPDX23JSON)
	require.NoError(t, err)

	out := writeSPDX(t, loaded)
	manifestSHA := fmt.Sprintf("%x", sha256.Sum256(in.Manifest))

	// ID of "manifest\n" plus the manifest SHA-256.
	manifest := packageByFileName(t, out, in.FileName)
	assert.Equal(t, "SPDXRef-79230f59-ce2a-5a2a-8c24-b526dba44211", manifest.SPDXID)
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: manifestSHA,
	}}, manifest.Checksums)

	// ID of "image\n" plus the image SHA-256.
	image := packageByFileName(t, out, img.FileName)
	assert.Equal(t, "SPDXRef-106e5ee0-643d-547f-89cf-e3f9765d482f", image.SPDXID)
	assert.Equal(t, []spdxChecksum{{
		Algorithm:     "SHA256",
		ChecksumValue: img.SHA256,
	}}, image.Checksums)

	assert.Contains(t, out.Relationships, spdxRelationship{
		Element: image.SPDXID,
		Related: manifest.SPDXID,
		Type:    "GENERATED_FROM",
	})
}

func TestSPDXRoundTripSameToolOmitsSecondCreator(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, s.Write(&buf, sbom.FormatSPDX23JSON))
	loaded, err := sbom.Read(&buf, sbom.FormatSPDX23JSON)
	require.NoError(t, err)

	require.NoError(t, loaded.AddImage(testImage, testInputs.Manifest, testInputs.Creator))

	assert.Equal(t, []string{
		"Tool: protobom-devel",
		"Tool: image-builder-1.2.3",
	}, writeSPDX(t, loaded).CreationInfo.Creators)
}

func TestSPDXRoundTripDifferentToolRecordsBoth(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, s.Write(&buf, sbom.FormatSPDX23JSON))
	loaded, err := sbom.Read(&buf, sbom.FormatSPDX23JSON)
	require.NoError(t, err)

	require.NoError(t, loaded.AddImage(testImage, testInputs.Manifest, sbom.Creator{
		Tool: sbom.ToolInfo{Name: "image-builder", Version: "2.3.4"},
	}))

	assert.Equal(t, []string{
		"Tool: protobom-devel",
		"Tool: image-builder-1.2.3",
		"Tool: image-builder-2.3.4",
	}, writeSPDX(t, loaded).CreationInfo.Creators)
}

func TestSPDXSameVersionOmitsSecondCreator(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	require.NoError(t, s.AddImage(testImage, testInputs.Manifest, testInputs.Creator))

	out := writeSPDX(t, s)
	assertDocumentNamespace(t, testImage.Name, out.DocumentNamespace)
	assert.Equal(t, []string{"Tool: protobom-devel", "Tool: image-builder-1.2.3"}, out.CreationInfo.Creators)
}

// Rebuilding for the same organization does not record it twice.
func TestSPDXAddImageSameOrganization(t *testing.T) {
	in := testInputs
	in.Creator.Organization = "Red Hat"

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	require.NoError(t, s.AddImage(testImage, in.Manifest, in.Creator))

	out := writeSPDX(t, s)
	assertDocumentNamespace(t, testImage.Name, out.DocumentNamespace)
	assert.Equal(t, []string{
		"Tool: protobom-devel",
		"Tool: image-builder-1.2.3",
		"Organization: Red Hat",
	}, out.CreationInfo.Creators)
	assert.Equal(t, "Organization: Red Hat", packageNamed(t, out, testImage.Name).Supplier)
}

// A later build by a different organization records that organization too,
// and supplies the image. The manifest keeps the organization that created it.
func TestSPDXAddImageDifferentOrganization(t *testing.T) {
	in := testInputs
	in.Creator.Organization = "Red Hat"

	s, err := sbom.Generate(in)
	require.NoError(t, err)

	creator := in.Creator
	creator.Organization = "Fedora Project"
	require.NoError(t, s.AddImage(testImage, in.Manifest, creator))

	out := writeSPDX(t, s)
	assert.Equal(t, []string{
		"Tool: protobom-devel",
		"Tool: image-builder-1.2.3",
		"Organization: Red Hat",
		"Organization: Fedora Project",
	}, out.CreationInfo.Creators)
	assert.Equal(t, "Organization: Red Hat", packageNamed(t, out, in.Name).Supplier)
	assert.Equal(t, "Organization: Fedora Project", packageNamed(t, out, testImage.Name).Supplier)
}

func TestAddImageRejectsEmptyName(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	before := writeSPDX(t, s)

	img := testImage
	img.Name = ""
	err = s.AddImage(img, testInputs.Manifest, testInputs.Creator)
	assert.ErrorContains(t, err, "image name is missing")
	assert.Equal(t, before, writeSPDX(t, s))
}

// AddImage stores the image digest as the root checksum, so it must be a
// SHA-256: 64 hex characters. An empty digest is missing; anything else that
// is not a SHA-256 is invalid. Either way the document is left unchanged.
func TestAddImageRejectsEmptyToolName(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	before := writeSPDX(t, s)

	err = s.AddImage(testImage, testInputs.Manifest, sbom.Creator{Tool: sbom.ToolInfo{Version: "1.2.3"}})
	assert.ErrorContains(t, err, "tool name is missing")
	assert.Equal(t, before, writeSPDX(t, s))
}

func TestAddImageRejectsEmptyVersion(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	before := writeSPDX(t, s)

	err = s.AddImage(testImage, testInputs.Manifest, sbom.Creator{Tool: sbom.ToolInfo{Name: "image-builder"}})
	assert.ErrorContains(t, err, "tool version is missing")
	assert.Equal(t, before, writeSPDX(t, s))
}

func TestAddImageRejectsInvalidSHA256(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sha256  string
		wantErr string
	}{
		{name: "empty", sha256: "", wantErr: "image sha256 is missing"},
		{name: "too short", sha256: strings.Repeat("a", 63), wantErr: "invalid image sha256"},
		{name: "too long", sha256: strings.Repeat("a", 65), wantErr: "invalid image sha256"},
		{name: "non-hex", sha256: strings.Repeat("g", 64), wantErr: "invalid image sha256"},
		{name: "uppercase", sha256: strings.Repeat("A", 64), wantErr: "invalid image sha256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := sbom.Generate(testInputs)
			require.NoError(t, err)

			before := writeSPDX(t, s)

			img := testImage
			img.SHA256 = tc.sha256
			err = s.AddImage(img, testInputs.Manifest, testInputs.Creator)
			require.ErrorContains(t, err, tc.wantErr)
			assert.Equal(t, before, writeSPDX(t, s))
		})
	}
}

func TestAddImageRejectsWrongManifest(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest []byte
		wantErr  string
	}{
		{
			name:     "different manifest",
			manifest: []byte(`{"version": "1", "pipelines": [], "sources": {}}`),
			wantErr:  "manifest sha256 mismatch",
		},
		{
			name:     "empty manifest",
			manifest: nil,
			wantErr:  "provided manifest is empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := sbom.Generate(testInputs)
			require.NoError(t, err)

			before := writeSPDX(t, s)

			err = s.AddImage(testImage, tc.manifest, testInputs.Creator)
			require.ErrorContains(t, err, tc.wantErr)

			assert.Equal(t, before, writeSPDX(t, s))
		})
	}
}

// The root is the manifest only while its SHA-256 matches the manifest bytes.
// After AddImage the image is the root, so the same bytes no longer match.
func TestAddImageRejectsImageRoot(t *testing.T) {
	s, err := sbom.Generate(testInputs)
	require.NoError(t, err)

	require.NoError(t, s.AddImage(testImage, testInputs.Manifest, testInputs.Creator))

	before := writeSPDX(t, s)

	err = s.AddImage(testImage, testInputs.Manifest, testInputs.Creator)
	require.ErrorContains(t, err, "manifest sha256 mismatch")
	assert.Equal(t, before, writeSPDX(t, s))
}
