package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	main "github.com/osbuild/image-builder/cmd/image-builder"
	"github.com/osbuild/image-builder/internal/testutil"
	"github.com/osbuild/image-builder/pkg/arch"
	testrepos "github.com/osbuild/image-builder/test/data/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTaskIntegrationArgs(t *testing.T) {
	restore := main.MockManifestgenDepsolver(fakeDepsolve)
	defer restore()

	restore = main.MockManifestgenContainerResolver(fakeContainerResolver)
	defer restore()

	restore = main.MockNewRepoRegistry(testrepos.New)
	defer restore()

	currentArch := arch.Current().String()
	prefix := func(s string) string {
		return fmt.Sprintf("centos-9-qcow2-%s.%s", currentArch, s)
	}
	for idx, tc := range []struct {
		args []string

		// expected files after task init
		expectedFilesInit []string

		// expected files after task build (not including expectedFilesInit)
		expectedFilesBuild []string
	}{
		{
			args:               nil,
			expectedFilesInit:  []string{prefix("manifest.json"), "sbom-contents.json"},
			expectedFilesBuild: []string{prefix("qcow2")},
		},
		{
			args:               []string{"--with-buildlog"},
			expectedFilesInit:  []string{prefix("manifest.json"), "sbom-contents.json"},
			expectedFilesBuild: []string{prefix("qcow2"), prefix("buildlog")},
		},
		{
			args:               []string{"--with-buildlog", "--with-rpmlist"},
			expectedFilesInit:  []string{prefix("manifest.json"), "sbom-contents.json", prefix("rpmlist.json")},
			expectedFilesBuild: []string{prefix("qcow2"), prefix("buildlog")},
		},
	} {
		t.Run(fmt.Sprintf("case%02d", idx), func(t *testing.T) {

			var expFiles []string
			taskdir := t.TempDir()

			t.Run("init", func(t *testing.T) {
				require := require.New(t)

				args := []string{"task", "init", "--image-type", "qcow2", "--distro", "centos-9", taskdir}
				args = append(args, tc.args...)
				restore = main.MockOsArgs(args)
				defer restore()

				osbuildCmd := testutil.MockCommand(t, "osbuild", makeFakeOsbuildScript())
				require.NoError(main.Run())

				// first call is --version for writing the version to the sidecar
				require.Equal([]string{"--version"}, osbuildCmd.CallArgsList()[0])

				// check expected files after init
				actFiles := dirRelative(t, taskdir)

				// we always expect task.json
				expFiles = append(tc.expectedFilesInit, "task.json")
				require.ElementsMatch(expFiles, actFiles)
			})

			t.Run("prefetch", func(t *testing.T) {
				require := require.New(t)

				args := []string{"task", "prefetch", taskdir}
				restore = main.MockOsArgs(args)
				defer restore()

				osbuildCmd := testutil.MockCommand(t, "osbuild", makeFakeOsbuildScript())
				require.NoError(main.Run())

				// first call is --version for comparing the version to the sidecar
				require.Equal([]string{"--version"}, osbuildCmd.CallArgsList()[0])

				// second call sets cache dir to download sources
				expArgs := []string{
					"--store", fmt.Sprintf("%s/cache", taskdir),

					// the following are always added
					"--output-directory", "", // not set but the option is always passed
					"--cache-max-size=21474836480",
					"-",
				}
				require.Equal(expArgs, osbuildCmd.CallArgsList()[1])

				// check expected files after prefetch
				actFiles := dirRelative(t, taskdir)
				expFiles = append(expFiles, "cache") // add cache to previous expected files
				require.ElementsMatch(expFiles, actFiles)
			})

			t.Run("build", func(t *testing.T) {
				require := require.New(t)

				args := []string{"task", "build-image", taskdir}
				restore = main.MockOsArgs(args)
				defer restore()

				osbuildCmd := testutil.MockCommand(t, "osbuild", makeFakeOsbuildScript())
				require.NoError(main.Run())

				// first call is --version for comparing the version to the sidecar
				require.Equal([]string{"--version"}, osbuildCmd.CallArgsList()[0])

				// second call to build the image
				expArgs := []string{
					"--store", fmt.Sprintf("%s/cache", taskdir),
					"--output-directory", taskdir,
					"--cache-max-size=21474836480",
					"-",
					"--export", "qcow2",
				}
				require.Equal(expArgs, osbuildCmd.CallArgsList()[1])

				// check expected files after build
				actFiles := dirRelative(t, taskdir)
				expFiles = append(expFiles, tc.expectedFilesBuild...) // append to previous expected files
				require.ElementsMatch(expFiles, actFiles)
			})
		})
	}
}

// returns a list of filenames in a dir with dir stripped
func dirRelative(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(dir + "/*")
	if err != nil {
		t.Fatalf("failed to glob for files in %q: %s", dir, err)
	}

	stripped := make([]string, len(paths))
	for idx, path := range paths {
		stripped[idx] = strings.TrimPrefix(path, dir+"/")
	}

	return stripped
}

// initSBOMTask exercises real task initialization while isolating external tools.
func initSBOMTask(t *testing.T, options ...string) string {
	t.Helper()
	mockSBOMManifestGeneration(t)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "nested"), 0755))
	args := append([]string{"task", "init", "--image-type", "qcow2", "--distro", "centos-9", dir}, options...)
	restore := main.MockOsArgs(args)
	defer restore()
	testutil.MockCommand(t, "osbuild", makeFakeOsbuildScript())
	require.NoError(t, main.Run())
	return dir
}

func rewriteTask(t *testing.T, dir string, edit func(map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, "task.json")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var task map[string]any
	require.NoError(t, json.Unmarshal(data, &task))
	edit(task)
	data, err = json.Marshal(task)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestTaskBuildWithSBOM(t *testing.T) {
	dir := initSBOMTask(t, "--output-name", "nested/document")
	// The export destination is authoritative, not the document basename or
	// image type. A decoy at the old guessed name must not be hashed instead.
	rewriteTask(t, dir, func(task map[string]any) { task["exports"] = map[string]string{"qcow2": "actual"} })
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nested/document.qcow2"), []byte("old image"), 0o600))
	t.Cleanup(main.MockOsArgs([]string{"task", "build-image", "--with-sbom", dir}))
	testutil.MockCommand(t, "osbuild", strings.ReplaceAll(makeFakeOsbuildScript(), "disk.qcow2", "disk.raw.xz"))
	require.NoError(t, main.Run())
	assertImageSBOM(t, filepath.Join(dir, "nested/document.spdx.json"), "nested/document", filepath.Join(dir, "actual.raw.xz"))
}

func TestTaskBuildWithSBOMRejectsUnsupported(t *testing.T) {
	for _, kind := range []string{"extras", "ostree"} {
		t.Run(kind, func(t *testing.T) {
			var opts []string
			expected := "--with-sbom cannot be combined with --with-extra"
			if kind == "ostree" {
				opts = []string{"--image-type", "edge-commit"}
				expected = "ostree-based image type"
			}
			dir := initSBOMTask(t, opts...)
			if kind == "extras" {
				rewriteTask(t, dir, func(task map[string]any) { task["exports"].(map[string]any)["sysext-nginx-erofs"] = "nginx" })
			}
			t.Cleanup(main.MockOsArgs([]string{"task", "build-image", "--with-sbom", dir}))
			cmd := testutil.MockCommand(t, "osbuild", makeFakeOsbuildScript())
			require.ErrorContains(t, main.Run(), expected)
			assertOnlyOSBuildVersion(t, cmd.CallArgsList())
			assertNoBuildOutputs(t, dir)
		})
	}
}

func TestTaskBuildWithSBOMRejectsInvalidContents(t *testing.T) {
	for content, expected := range map[string]string{
		"missing": "SBOM contents not found", "null": "SBOM inventory is empty",
		"{}": "decoding SBOM contents", "[]": "SBOM inventory is empty",
		"{not json": "decoding SBOM contents", "missing-checksum": "missing checksum", "conflict": "duplicate package",
	} {
		t.Run(content, func(t *testing.T) {
			dir := initSBOMTask(t)
			path := filepath.Join(dir, "sbom-contents.json")
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var packages []map[string]any
			require.NoError(t, json.Unmarshal(data, &packages))
			switch content {
			case "missing":
				require.NoError(t, os.Remove(path))
			case "missing-checksum", "conflict":
				if content == "missing-checksum" {
					delete(packages[0], "Checksum")
				} else {
					duplicate := make(map[string]any)
					for k, v := range packages[0] {
						duplicate[k] = v
					}
					duplicate["Checksum"] = map[string]string{"Type": "sha256", "Value": strings.Repeat("a", 64)}
					packages = append(packages, duplicate)
				}
				data, err = json.Marshal(packages)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, data, 0o600))
			default:
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			}
			t.Cleanup(main.MockOsArgs([]string{"task", "build-image", "--with-sbom", dir}))
			cmd := testutil.MockCommand(t, "osbuild", makeFakeOsbuildScript())
			require.ErrorContains(t, main.Run(), expected)
			assertOnlyOSBuildVersion(t, cmd.CallArgsList())
			assertNoBuildOutputs(t, dir)
		})
	}
}

func assertOnlyOSBuildVersion(t *testing.T, calls [][]string) {
	t.Helper()
	for _, args := range calls {
		assert.Equal(t, []string{"--version"}, args)
	}
}

func assertNoBuildOutputs(t *testing.T, dir string) {
	t.Helper()
	for _, pattern := range []string{"*.qcow2", "*spdx*"} {
		paths, err := filepath.Glob(filepath.Join(dir, pattern))
		require.NoError(t, err)
		assert.Empty(t, paths)
	}
}

func TestBuildWithSBOMOutputCardinality(t *testing.T) {
	for _, task := range []bool{false, true} {
		for _, count := range []int{0, 2} {
			t.Run(fmt.Sprintf("task=%v/count=%d", task, count), func(t *testing.T) {
				dir := initSBOMTask(t)
				args := []string{"task", "build-image", "--with-sbom", dir}
				if !task {
					args = []string{"build", "qcow2", "--distro", "centos-9", "--cache", t.TempDir(), "--output-dir", dir, "--with-sbom"}
				}
				restore := main.MockOsArgs(args)
				defer restore()
				script := strings.ReplaceAll(makeFakeOsbuildScript(), `echo "fake-img-qcow2" > "$output_dir/$export/disk.qcow2"`, "")
				if count == 2 {
					script += `
    echo first > "$output_dir/$export/disk.qcow2"
    echo second > "$output_dir/$export/disk.raw.xz"
    `
				}
				testutil.MockCommand(t, "osbuild", script)
				require.ErrorContains(t, main.Run(), fmt.Sprintf("--with-sbom requires exactly one output artifact, got %d", count))
				docs, err := filepath.Glob(filepath.Join(dir, "*.spdx.json"))
				require.NoError(t, err)
				assert.Empty(t, docs)
				if count == 2 {
					// Without SBOM, multiple artifacts retain their existing behavior.
					restore()
					args = slices.DeleteFunc(args, func(arg string) bool { return arg == "--with-sbom" })
					restore = main.MockOsArgs(args)
					defer restore()
					require.NoError(t, main.Run())
					for _, ext := range []string{"qcow2", "raw.xz"} {
						paths, err := filepath.Glob(filepath.Join(dir, "*."+ext))
						require.NoError(t, err)
						assert.Len(t, paths, 1)
					}
				}
			})
		}
	}
}
