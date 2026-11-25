package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/osbuild/image-builder/pkg/hashutil"
	"github.com/osbuild/image-builder/pkg/sbom"
)

func writeImageSBOM(outputDir, basename string, outputPaths []string, doc *sbom.Document) error {
	if len(outputPaths) != 1 {
		return fmt.Errorf("SBOM generation requires exactly one image artifact, got %d", len(outputPaths))
	}
	imagePath := outputPaths[0]
	info, err := os.Stat(imagePath)
	if err != nil {
		return fmt.Errorf("checking built artifact for SBOM: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("cannot hash directory export %q for SBOM: a regular file is required; use manifest --with-sbom for a pre-build SBOM without an artifact digest", imagePath)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cannot hash export %q for SBOM: not a regular file", imagePath)
	}
	sum, err := hashutil.Sha256sum(imagePath)
	if err != nil {
		return fmt.Errorf("hashing built image for SBOM: %w", err)
	}
	if err := doc.SetArtifact(filepath.Base(imagePath), sum); err != nil {
		return err
	}
	return writeSBOM(outputDir, basename, doc)
}

func writeSBOM(outputDir, basename string, doc *sbom.Document) error {
	var buf bytes.Buffer
	if err := doc.Write(&buf, sbom.FormatSPDX23JSON); err != nil {
		return err
	}
	path := filepath.Join(outputDir, basename+".spdx.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// #nosec: G306
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

const taskSBOMName = "sbom.pb"

func writeTaskSBOM(workdir string, doc *sbom.Document) error {
	var buf bytes.Buffer
	if err := doc.WriteProto(&buf); err != nil {
		return fmt.Errorf("encoding task SBOM: %w", err)
	}
	path := filepath.Join(workdir, taskSBOMName)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing task SBOM %q: %w", path, err)
	}
	return nil
}

func readTaskSBOM(workdir string) (*sbom.Document, error) {
	path := filepath.Join(workdir, taskSBOMName)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening task SBOM %q: %w", path, err)
	}
	defer f.Close()

	doc, err := sbom.ReadProto(f)
	if err != nil {
		return nil, fmt.Errorf("decoding task SBOM %q: %w", path, err)
	}
	return doc, nil
}
