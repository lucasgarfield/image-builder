package sbom

import (
	"maps"
	"slices"
	"strings"

	rpmversion "github.com/knqyf263/go-rpm-version"
	"github.com/osbuild/image-builder/pkg/rpmmd"
	pb "github.com/protobom/protobom/pkg/sbom"
)

// Requires/Provides describe capabilities, not the solver's choice between
// alternatives. Emit only uniquely attributable hard requirements in the same
// pipeline. Missing metadata, rich requirements and ambiguous providers are
// not evidence of a particular package dependency.
func rpmDependencies(pipeline string, packages []rpmmd.Package) []*pb.Edge {
	type provider struct{ id, version string }
	providers := map[string][]provider{}
	needed := map[string]bool{}
	for _, p := range packages {
		for _, req := range p.Requires {
			needed[req.Name] = true
		}
	}
	// A ranged provide is not an exact version. Don't guess a winner for this capability.
	uncertain := map[string]bool{}
	ids := make([]string, len(packages))
	for i, p := range packages {
		id := rpmID(pipeline, rpmPURL(p))
		ids[i] = id
		providers[p.Name] = append(providers[p.Name], provider{id, strings.TrimSuffix(p.EVRA(), "."+p.Arch)})
		for _, cap := range p.Provides {
			if !needed[cap.Name] {
				continue
			}
			if cap.Relationship != "=" && cap.Relationship != "" {
				uncertain[cap.Name] = true
				continue
			}
			providers[cap.Name] = append(providers[cap.Name], provider{id, cap.Version})
		}
		for _, file := range p.Files {
			if needed[file] {
				providers[file] = append(providers[file], provider{id, ""})
			}
		}
	}
	links := map[string]map[string]bool{}
	for i, p := range packages {
		for _, req := range p.Requires {
			if uncertain[req.Name] || strings.HasPrefix(req.Name, "(") {
				continue
			}
			var target string
			for _, cap := range providers[req.Name] {
				if !satisfies(cap.version, req) {
					continue
				}
				if target != "" && target != cap.id {
					target = ""
					break
				}
				target = cap.id
			}
			if target != "" && target != ids[i] {
				if links[ids[i]] == nil {
					links[ids[i]] = map[string]bool{}
				}
				links[ids[i]][target] = true
			}
		}
	}
	var edges []*pb.Edge
	for _, id := range slices.Sorted(maps.Keys(links)) {
		edges = append(edges, &pb.Edge{Type: pb.Edge_dependsOn, From: id, To: slices.Sorted(maps.Keys(links[id]))})
	}
	return edges
}

func satisfies(provided string, req rpmmd.RelDep) bool {
	if req.Relationship == "" {
		return req.Version == ""
	}
	if provided == "" || req.Version == "" {
		return false
	}
	// rpmverOverlap compares releases only when both are present. At the
	// same epoch/version an equality provide with no release overlaps even
	// a strict, release-qualified requirement.
	releaseLessProvide := !strings.Contains(provided, "-") && strings.Contains(req.Version, "-")
	required := req.Version
	if !strings.Contains(required, "-") || !strings.Contains(provided, "-") {
		provided, _, _ = strings.Cut(provided, "-")
		required, _, _ = strings.Cut(required, "-")
	}
	cmp := rpmversion.NewVersion(provided).Compare(rpmversion.NewVersion(required))
	if cmp == 0 && releaseLessProvide {
		return true
	}
	switch req.Relationship {
	case "=":
		return cmp == 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	}
	return false
}
