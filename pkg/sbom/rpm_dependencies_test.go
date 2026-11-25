package sbom

import (
	"testing"

	"github.com/osbuild/image-builder/pkg/rpmmd"
	pb "github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

func TestRPMRequirementProviders(t *testing.T) {
	provider := rpmmd.Package{Name: "tool", Version: "1.10", Release: "9", Arch: "x86_64", Provides: rpmmd.RelDepList{{Name: "api", Relationship: "=", Version: "1:1.10-9"}}, Files: []string{"/usr/bin/tool"}}
	another := provider
	another.Name = "alternative"
	noRelease := another
	noRelease.Provides = rpmmd.RelDepList{{Name: "api", Relationship: "=", Version: "1:1.10"}}
	for _, tc := range []struct {
		name      string
		req       rpmmd.RelDep
		providers []rpmmd.Package
		matched   bool
	}{
		{"virtual capability with epoch", rpmmd.RelDep{Name: "api", Relationship: ">=", Version: "1:1.2"}, []rpmmd.Package{provider}, true},
		{"version mismatch", rpmmd.RelDep{Name: "api", Relationship: ">", Version: "2:1"}, []rpmmd.Package{provider}, false},
		{"no release", rpmmd.RelDep{Name: "tool", Relationship: "=", Version: "1.10"}, []rpmmd.Package{provider}, true},
		{"release-less versioned provide", rpmmd.RelDep{Name: "api", Relationship: "=", Version: "1:1.10-9"}, []rpmmd.Package{noRelease}, true},
		{"overlapping provides", rpmmd.RelDep{Name: "api", Relationship: "=", Version: "1:1.10-9"}, []rpmmd.Package{provider, noRelease}, false},
		{"file", rpmmd.RelDep{Name: "/usr/bin/tool"}, []rpmmd.Package{provider}, true},
		{"ambiguous", rpmmd.RelDep{Name: "api"}, []rpmmd.Package{provider, another}, false},
		{"self", rpmmd.RelDep{Name: "consumer"}, nil, false},
		{"not installed", rpmmd.RelDep{Name: "missing"}, nil, false},
		{"rich", rpmmd.RelDep{Name: "(tool or alternative)"}, []rpmmd.Package{provider}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := rpmmd.Package{Name: "consumer", Requires: rpmmd.RelDepList{tc.req}}
			edges := rpmDependencies("os", append(tc.providers, c))
			if !tc.matched {
				require.Empty(t, edges)
				return
			}
			require.Len(t, edges, 1)
			require.Equal(t, pb.Edge_dependsOn, edges[0].Type)
			require.Equal(t, rpmID("os", rpmPURL(c)), edges[0].From)
			require.Equal(t, []string{rpmID("os", rpmPURL(tc.providers[0]))}, edges[0].To)
		})
	}
}
