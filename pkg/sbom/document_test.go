package sbom

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLegacySPDX(t *testing.T) {
	doc := Generate(Inputs{
		Creator: Creator{
			Name:    "image-builder",
			Version: "1.2",
		},
	})
	var buf bytes.Buffer
	require.NoError(t, doc.Write(&buf, FormatLegacyOSBuildSPDX))
	var got struct {
		SPDXVersion       string
		DataLicense       string
		SPDXID            string
		Name              string
		DocumentNamespace string
		CreationInfo      struct {
			Created  string
			Creators []string
		}
		Packages []json.RawMessage
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Equal(t, "SPDX-2.3", got.SPDXVersion)
	require.Equal(t, "CC0-1.0", got.DataLicense)
	require.Equal(t, "SPDXRef-DOCUMENT", got.SPDXID)
	require.Equal(t, "sbom-by-image-builder-1.2", got.Name)
	require.Regexp(t, `^https://osbuild\.org/spdxdocs/sbom-by-image-builder-1\.2-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, got.DocumentNamespace)
	created, err := time.Parse(time.RFC3339, got.CreationInfo.Created)
	require.NoError(t, err)
	require.Equal(t, created.UTC().Format(time.RFC3339), got.CreationInfo.Created)
	require.Equal(t, []string{"Tool: image-builder-1.2"}, got.CreationInfo.Creators)
	require.Equal(t, []json.RawMessage{}, got.Packages)
}

func TestLegacySPDXPackages(t *testing.T) {
	x64 := Package{
		Name:    "glibc",
		Epoch:   1,
		Version: "2.34",
		Release: "1.el9",
		Arch:    "x86_64",
		Vendor:  "Red Hat, Inc.",
	}
	i686 := x64
	i686.Arch = "i686"
	i686.DownloadURL = "https://example.org/glibc.i686.rpm"
	i686.Homepage = "https://example.org/glibc"
	i686.SourceRPM = "glibc-2.34-1.el9.src.rpm"
	i686.Summary = "C library"
	i686.Description = "The C library"
	i686.BuildTime = time.Date(2025, 6, 1, 14, 30, 59, 123, time.FixedZone("offset", 3600))
	doc := Generate(Inputs{
		Packages: []Package{x64, i686, x64},
	})
	var buf bytes.Buffer
	require.NoError(t, doc.Write(&buf, FormatLegacyOSBuildSPDX))
	var got struct {
		Packages      json.RawMessage
		Relationships json.RawMessage
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.JSONEq(t, `[
		{"SPDXID":"SPDXRef-1f0b4038-e85f-3269-9265-caca079be049","name":"glibc","downloadLocation":"NOASSERTION","filesAnalyzed":false,"versionInfo":"2.34"},
		{"SPDXID":"SPDXRef-f0de0b9a-586e-313d-86b6-9768212bf80f","name":"glibc","downloadLocation":"https://example.org/glibc.i686.rpm","filesAnalyzed":false,"versionInfo":"2.34","homepage":"https://example.org/glibc","sourceInfo":"Source RPM: glibc-2.34-1.el9.src.rpm","summary":"C library","description":"The C library","builtDate":"2025-06-01T13:30:59Z"}
	]`, string(got.Packages))
	require.JSONEq(t, `[
		{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-1f0b4038-e85f-3269-9265-caca079be049"},
		{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-f0de0b9a-586e-313d-86b6-9768212bf80f"}
	]`, string(got.Relationships))
}

func TestUnknownFormat(t *testing.T) {
	require.Error(t, Generate(Inputs{}).Write(io.Discard, Format("unknown")))
}
