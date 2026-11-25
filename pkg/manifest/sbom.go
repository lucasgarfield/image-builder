package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/osbuild/image-builder/pkg/container"
	"github.com/osbuild/image-builder/pkg/depsolvednf"
	"github.com/osbuild/image-builder/pkg/flatpak"
	"github.com/osbuild/image-builder/pkg/ostree"
	"github.com/osbuild/image-builder/pkg/sbom"
)

// SBOMGraph joins resolved inventories to the precise references used in the
// emitted manifest. Stage options and source references are not pipeline edges.
// Decode only this projection: stage inputs have several different wire types.
type SBOMGraph struct {
	pipelines map[string]sbom.Pipeline
}

func (m Manifest) SBOMGraph(serialized OSBuildManifest, sets map[string]depsolvednf.DepsolveResult, containers map[string][]container.Spec, commits map[string][]ostree.CommitSpec, flatpaks map[string][]flatpak.Spec) (*SBOMGraph, error) {
	var wire struct {
		Pipelines []struct {
			Name, Build string
			Stages      []struct {
				Inputs map[string]struct {
					Origin     string
					References json.RawMessage
				}
			}
		}
	}
	if err := json.Unmarshal(serialized, &wire); err != nil {
		return nil, err
	}
	g := &SBOMGraph{pipelines: map[string]sbom.Pipeline{}}
	definitions := map[string]Pipeline{}
	for _, p := range m.pipelines {
		definitions[p.Name()] = p
	}
	for _, w := range wire.Pipelines {
		def := definitions[w.Name]
		if def == nil {
			return nil, fmt.Errorf("unknown serialized pipeline %q", w.Name)
		}
		result, solved := sets[w.Name]
		if !solved {
			chain, err := def.getPackageSetChain(m.Distro)
			if err != nil {
				return nil, fmt.Errorf("checking package set chain for %q: %w", w.Name, err)
			}
			if len(chain) != 0 {
				return nil, fmt.Errorf("missing depsolve result for pipeline %q", w.Name)
			}
		}
		transactions := result.Transactions
		var reference Pipeline
		switch def := def.(type) {
		case *SysextTree:
			reference = def.depsolveReferencePipeline
			var err error
			transactions, err = def.installedTransactions(transactions)
			if err != nil {
				return nil, err
			}
		case *SysextPrep:
			reference = def.filesystemReferencePipeline
		}
		p := sbom.Pipeline{
			Role:       sbom.PipelinePayload,
			Packages:   transactions.AllPackages(),
			Containers: containers[w.Name], Commits: commits[w.Name], Flatpaks: flatpaks[w.Name],
		}
		if _, ok := def.(Build); ok {
			p.Role = sbom.PipelineBuildroot
		} else if def.getExport() {
			p.Role = sbom.PipelineArtifact
		}
		deps := map[string]bool{}
		for _, stage := range w.Stages {
			for _, input := range stage.Inputs {
				if input.Origin != "org.osbuild.pipeline" {
					continue
				}
				refs, err := pipelineReferences(input.References)
				if err != nil {
					return nil, fmt.Errorf("pipeline %q inputs: %w", w.Name, err)
				}
				for _, ref := range refs {
					deps[strings.TrimPrefix(ref, "name:")] = true
				}
			}
		}
		buildInputs := map[string]bool{}
		if w.Build != "" {
			buildInputs[strings.TrimPrefix(w.Build, "name:")] = true
		}
		// A sysext is a delta against a reference tree. Keep that input as
		// build provenance, not as part of the extension payload.
		if reference != nil && deps[reference.Name()] {
			delete(deps, reference.Name())
			buildInputs[reference.Name()] = true
		}
		p.BuildInputs = slices.Sorted(maps.Keys(buildInputs))
		p.Inputs = slices.Sorted(maps.Keys(deps))
		g.pipelines[w.Name] = p
	}
	return g, nil
}

func pipelineReferences(raw json.RawMessage) ([]string, error) {
	var keyed map[string]json.RawMessage
	if bytes.HasPrefix(raw, []byte("{")) {
		if err := json.Unmarshal(raw, &keyed); err != nil {
			return nil, err
		}
		return slices.Sorted(maps.Keys(keyed)), nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	var refs []string
	for _, item := range list {
		var ref string
		if bytes.HasPrefix(item, []byte("{")) {
			var entry struct{ ID string }
			if err := json.Unmarshal(item, &entry); err != nil {
				return nil, err
			}
			ref = entry.ID
		} else if err := json.Unmarshal(item, &ref); err != nil {
			return nil, err
		}
		if ref == "" {
			return nil, fmt.Errorf("empty pipeline reference")
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// Reachable returns the pipelines used by root (including root), in name order.
func (g *SBOMGraph) Reachable(root string, includeBuild bool) ([]string, error) {
	selected, err := g.selectPipelines(root, includeBuild)
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(selected)), nil
}

// Document describes only root and its transitive inputs. For an artifact SBOM,
// pass the export selected by the build request, not all exportable pipelines.
func (g *SBOMGraph) Document(in sbom.Inputs, root string, includeBuild bool) (*sbom.Document, error) {
	selected, err := g.selectPipelines(root, includeBuild)
	if err != nil {
		return nil, err
	}
	in.Pipelines = selected
	return sbom.Generate(in)
}

func (g *SBOMGraph) selectPipelines(root string, includeBuild bool) (map[string]sbom.Pipeline, error) {
	selected := map[string]sbom.Pipeline{}
	active := map[string]bool{}
	var visit func(string) error
	visit = func(name string) error {
		if active[name] {
			return fmt.Errorf("cycle at SBOM pipeline %q", name)
		}
		if _, done := selected[name]; done {
			return nil
		}
		p, ok := g.pipelines[name]
		if !ok {
			return fmt.Errorf("unknown SBOM pipeline %q", name)
		}
		active[name] = true
		if !includeBuild {
			p.BuildInputs = nil
		}
		for _, dep := range p.BuildInputs {
			if err := visit(dep); err != nil {
				return err
			}
		}
		for _, dep := range p.Inputs {
			if err := visit(dep); err != nil {
				return err
			}
		}
		delete(active, name)
		selected[name] = p
		return nil
	}
	if err := visit(root); err != nil {
		return nil, err
	}
	return selected, nil
}
