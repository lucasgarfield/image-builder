package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/osbuild/image-builder/pkg/hashutil"
	"github.com/osbuild/image-builder/pkg/sbom"
)

// writeImageSBOM writes an SPDX document for the built image next to it.
// The document is named for the image and checksummed against the file osbuild wrote.
func writeImageSBOM(outputDir, basename, imagePath string, packages []sbom.Package) (err error) {
	path := filepath.Join(outputDir, basename+".spdx.json")
	// Do not leave a previous document describing a newly replaced image if
	// publication fails. Builds without --with-sbom keep their existing behavior.
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	sum, err := hashutil.Sha256sum(imagePath)
	if err != nil {
		return fmt.Errorf("hashing built image for SBOM: %w", err)
	}
	doc, err := sbom.Generate(sbom.Inputs{
		Creator: sbom.Creator{
			Tool: sbom.ToolInfo{
				Name:    "image-builder",
				Version: version,
			},
		},
		Image: sbom.Image{
			Name:     basename,
			FileName: filepath.Base(imagePath),
			SHA256:   sum,
		},
		Packages: packages,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating SBOM %s: %w", path, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	// #nosec: G302
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return fmt.Errorf("setting permissions on SBOM %s: %w", tmp, err)
	}
	if err := doc.Write(f, sbom.FormatSPDX23JSON); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing SBOM %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing SBOM %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renaming SBOM %s to %s: %w", tmp, path, err)
	}
	return nil
}

// Task init persists only the RPM inventory, separately from task.json.
const taskSBOMContentsName = "sbom-contents.json"

func writeTaskSBOMContents(workdir string, packages []sbom.Package) error {
	data, err := json.Marshal(packages)
	if err != nil {
		return fmt.Errorf("encoding SBOM contents: %w", err)
	}
	path := filepath.Join(workdir, taskSBOMContentsName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing SBOM contents %s: %w", path, err)
	}
	return nil
}

func readTaskSBOMContents(workdir string) ([]sbom.Package, error) {
	path := filepath.Join(workdir, taskSBOMContentsName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("SBOM contents not found at %q: see 'image-builder task init --help'", path)
	}
	if err != nil {
		return nil, fmt.Errorf("reading SBOM contents %s: %w", path, err)
	}
	var packages []sbom.Package
	if err := json.Unmarshal(data, &packages); err != nil {
		return nil, fmt.Errorf("decoding SBOM contents %s: %w", path, err)
	}
	if err := validateSBOMPackages(packages); err != nil {
		return nil, err
	}
	return packages, nil
}

func validateSBOMPackages(packages []sbom.Package) error {
	if len(packages) == 0 {
		return errors.New("SBOM inventory is empty")
	}
	if err := sbom.ValidatePackages(packages); err != nil {
		return fmt.Errorf("invalid SBOM inventory: %w", err)
	}
	return nil
}
