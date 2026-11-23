package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// Creator identifies the tool that made the document.
type Creator struct {
	Name    string
	Version string
}

// Package describes a package included in the document.
type Package struct{}

// Inputs holds the information used to generate a document.
type Inputs struct {
	Creator  Creator
	Packages []Package
}

// Document is an in-memory software bill of materials.
type Document struct {
	creator Creator
	id      uuid.UUID
	created time.Time
}

// Generate builds a new document from the supplied inputs.
func Generate(in Inputs) *Document {
	return &Document{
		creator: in.Creator,
		id:      uuid.New(),
		created: time.Now().UTC(),
	}
}

// Format selects the output representation of a document.
type Format string

// FormatLegacyOSBuildSPDX selects the SPDX 2.3 JSON format used by osbuild.
const FormatLegacyOSBuildSPDX Format = "osbuild-spdx"

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxDocument struct {
	SPDXID            string       `json:"SPDXID"`
	CreationInfo      creationInfo `json:"creationInfo"`
	DataLicense       string       `json:"dataLicense"`
	Name              string       `json:"name"`
	SPDXVersion       string       `json:"spdxVersion"`
	DocumentNamespace string       `json:"documentNamespace"`
	Packages          []Package    `json:"packages"`
}

// Write encodes the document as JSON in the selected format.
func (d *Document) Write(w io.Writer, format Format) error {
	if format != FormatLegacyOSBuildSPDX {
		return fmt.Errorf("unknown SBOM format: %q", format)
	}
	tool := d.creator.Name + "-" + d.creator.Version
	name := "sbom-by-" + tool
	return json.NewEncoder(w).Encode(spdxDocument{
		SPDXID: "SPDXRef-DOCUMENT",
		CreationInfo: creationInfo{
			Created:  d.created.Format(time.RFC3339),
			Creators: []string{"Tool: " + tool},
		},
		DataLicense:       "CC0-1.0",
		Name:              name,
		SPDXVersion:       "SPDX-2.3",
		DocumentNamespace: "https://osbuild.org/spdxdocs/" + name + "-" + d.id.String(),
		Packages:          []Package{},
	})
}
