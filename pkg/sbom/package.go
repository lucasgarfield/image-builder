package sbom

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Package describes a depsolved RPM included in the document.
type Package struct {
	Name        string
	Epoch       uint
	Version     string
	Release     string
	Arch        string
	Vendor      string
	DownloadURL string
	Homepage    string
	SourceRPM   string
	Summary     string
	Description string
	BuildTime   time.Time
}

func (p Package) spdxID() string {
	namespace := ""
	if p.Vendor != "" {
		vendor := url.QueryEscape(strings.ToLower(p.Vendor))
		namespace = strings.NewReplacer("+", "%20", "%2F", "/").Replace(vendor) + "/"
	}
	purl := fmt.Sprintf("pkg:rpm/%s%s@%s-%s?arch=%s", namespace, p.Name, p.Version, p.Release, p.Arch)
	if p.Epoch != 0 {
		purl += fmt.Sprintf("&epoch=%d", p.Epoch)
	}
	return "SPDXRef-" + uuid.NewMD5(uuid.NameSpaceURL, []byte(purl)).String()
}

type spdxPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	Homepage         string `json:"homepage,omitempty"`
	SourceInfo       string `json:"sourceInfo,omitempty"`
	Summary          string `json:"summary,omitempty"`
	Description      string `json:"description,omitempty"`
	BuiltDate        string `json:"builtDate,omitempty"`
}

func (p Package) toSPDX(id string) spdxPackage {
	pkg := spdxPackage{
		SPDXID:           id,
		Name:             p.Name,
		DownloadLocation: p.DownloadURL,
		FilesAnalyzed:    false,
		VersionInfo:      p.Version,
		Homepage:         p.Homepage,
		Summary:          p.Summary,
		Description:      p.Description,
	}
	if pkg.DownloadLocation == "" {
		pkg.DownloadLocation = "NOASSERTION"
	}
	if p.SourceRPM != "" {
		pkg.SourceInfo = "Source RPM: " + p.SourceRPM
	}
	if !p.BuildTime.IsZero() {
		pkg.BuiltDate = p.BuildTime.UTC().Format(time.RFC3339)
	}
	return pkg
}
