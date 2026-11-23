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

func TestUnknownFormat(t *testing.T) {
	require.Error(t, Generate(Inputs{}).Write(io.Discard, Format("unknown")))
}
