package tests

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// integrationCase describes one end-to-end CLI scenario.
type integrationCase struct {
	// archives are extracted from fixturesDir into the temp dir before setup.
	archives []string
	// setup corrupts or mutates the extracted files; returns files to verify
	// after repair (keyed by path relative to dir). May be nil.
	setup func(t *testing.T, dir string) map[string][]byte
	// cmdDir is a subdirectory of dir from which the CLI is invoked.
	// Empty means the CLI runs from dir itself.
	cmdDir   string
	subcmd   string // "verify" or "repair"
	par2file string
	wantCode int // expected process exit code
	// check runs additional assertions after the CLI exits. May be nil.
	check func(t *testing.T, dir string, originals map[string][]byte)
}

var integrationCases = map[string]integrationCase{
	// ── verify ─────────────────────────────────────────────────────────────

	"verify_healthy_par2": {
		archives: []string{"flatdata.tar.gz", "flatdata-par2files.tar.gz"},
		subcmd:   "verify",
		par2file: "testdata.par2",
		wantCode: 0,
	},

	"verify_reports_missing_file": {
		archives: []string{"flatdata.tar.gz", "flatdata-par2files.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			mustRemove(t, filepath.Join(dir, "test-1.data"))
			return nil
		},
		subcmd:   "verify",
		par2file: "testdata.par2",
		wantCode: 1,
	},

	"verify_reports_corrupted_file": {
		archives: []string{"flatdata.tar.gz", "flatdata-par2files.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			flipByteAt(t, filepath.Join(dir, "test-3.data"), 100)
			return nil
		},
		subcmd:   "verify",
		par2file: "testdata.par2",
		wantCode: 1,
	},

	// bug128: a zero-byte extra file in the directory must not crash verify.
	"verify_ignores_zero_byte_extra_file": {
		archives: []string{"flatdata.tar.gz", "bug128-parfiles.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			f, err := os.Create(filepath.Join(dir, "test-a.data"))
			if err != nil {
				t.Fatalf("create zero-byte file: %v", err)
			}
			_ = f.Close()
			return nil
		},
		subcmd:   "verify",
		par2file: "recovery.par2",
		wantCode: 0,
	},

	// ── repair: flat data ───────────────────────────────────────────────────

	"repair_two_deleted_files": {
		archives: []string{"flatdata.tar.gz", "flatdata-par2files.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			orig := readFiles(t, dir, "test-1.data", "test-3.data")
			mustRemove(t, filepath.Join(dir, "test-1.data"))
			mustRemove(t, filepath.Join(dir, "test-3.data"))
			return orig
		},
		subcmd:   "repair",
		par2file: "testdata.par2",
		wantCode: 0,
		check:    assertFilesRestored,
	},

	"repair_deleted_and_corrupted": {
		archives: []string{"flatdata.tar.gz", "flatdata-par2files.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			orig := readFiles(t, dir, "test-1.data", "test-3.data")
			mustRemove(t, filepath.Join(dir, "test-1.data"))
			flipByteAt(t, filepath.Join(dir, "test-3.data"), 100)
			return orig
		},
		subcmd:   "repair",
		par2file: "testdata.par2",
		wantCode: 0,
		check:    assertFilesRestored,
	},

	"repair_corruption_at_start_of_file": {
		archives: []string{"flatdata.tar.gz", "flatdata-par2files.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			orig := readFiles(t, dir, "test-2.data")
			flipByteAt(t, filepath.Join(dir, "test-2.data"), 0)
			return orig
		},
		subcmd:   "repair",
		par2file: "testdata.par2",
		wantCode: 0,
		check:    assertFilesRestored,
	},

	"repair_corruption_at_end_of_file": {
		archives: []string{"flatdata.tar.gz", "flatdata-par2files.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			orig := readFiles(t, dir, "test-2.data")
			flipLastByte(t, filepath.Join(dir, "test-2.data"))
			return orig
		},
		subcmd:   "repair",
		par2file: "testdata.par2",
		wantCode: 0,
		check:    assertFilesRestored,
	},

	// bug128: zero-byte extra file must not interfere with repair.
	"repair_with_zero_byte_extra_file": {
		archives: []string{"flatdata.tar.gz", "bug128-parfiles.tar.gz"},
		subcmd:   "repair",
		par2file: "recovery.par2",
		wantCode: 0,
	},

	// ── repair: subdirectory layouts ───────────────────────────────────────

	// test6 equivalent: par2 files generated on a Unix system.
	"repair_files_in_subdirs_unix_par2": {
		archives: []string{"subdirdata.tar.gz", "subdirdata-par2files-unix.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			orig := readFiles(t, dir, "subdir1/test-2.data", "subdir2/test-7.data")
			mustRemove(t, filepath.Join(dir, "subdir1/test-2.data"))
			mustRemove(t, filepath.Join(dir, "subdir2/test-7.data"))
			return orig
		},
		subcmd:   "repair",
		par2file: "testdata.par2",
		wantCode: 0,
		check:    assertFilesRestored,
	},

	// test7 equivalent: par2 files generated on Windows (backslash paths in packets).
	// Exercises DefangPath backslash normalisation in the decoder.
	"repair_files_in_subdirs_windows_par2": {
		archives: []string{"subdirdata.tar.gz", "subdirdata-par2files-win.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			orig := readFiles(t, dir, "subdir1/test-2.data", "subdir2/test-7.data")
			mustRemove(t, filepath.Join(dir, "subdir1/test-2.data"))
			mustRemove(t, filepath.Join(dir, "subdir2/test-7.data"))
			return orig
		},
		subcmd:   "repair",
		par2file: "testdata.par2",
		wantCode: 0,
		check:    assertFilesRestored,
	},

	// test10 equivalent: entire subdir deleted — repair must recreate the directory.
	"repair_entire_subdir_deleted": {
		archives: []string{"smallsubdirdata.tar.gz", "smallsubdirdata-par2files.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			orig := readFiles(t, dir, "subdir1/test-0.data")
			mustRemoveAll(t, filepath.Join(dir, "subdir1"))
			return orig
		},
		subcmd:   "repair",
		par2file: "testdata.par2",
		wantCode: 0,
		check:    assertFilesRestored,
	},

	// test17 equivalent (bug44): nested subdir structure deleted.
	"repair_nested_subdir_deleted": {
		archives: []string{"bug44.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			orig := readFiles(t, dir,
				"subdir1/subsubdir1/test-0.data",
				"subdir1/subsubdir1/test-2.data",
				"subdir1/subsubdir1/test-4.data",
				"subdir1/subsubdir1/test-6.data",
				"subdir1/subsubdir1/test-8.data",
			)
			mustRemoveAll(t, filepath.Join(dir, "subdir1"))
			return orig
		},
		subcmd:   "repair",
		par2file: "recovery.par2",
		wantCode: 0,
		check:    assertFilesRestored,
	},

	// ── repair: edge-case archives ──────────────────────────────────────────

	// test12 equivalent: file truncated to wrong size.
	"repair_truncated_file": {
		archives: []string{"readbeyondeof.tar.gz"},
		setup: func(t *testing.T, dir string) map[string][]byte {
			truncateFile(t, filepath.Join(dir, "test.data"), 113579)
			return nil
		},
		subcmd:   "repair",
		par2file: "test.par2",
		wantCode: 0,
	},

	// test15 equivalent: known crash-inducing archive from issue #35.
	"repair_crash_regression_issue35": {
		archives: []string{"par2-0.6.8-crash.tar.gz"},
		cmdDir:   "par2-0.6.8-crash",
		subcmd:   "repair",
		par2file: "pack-ea5f7f848340980493ed39f5b7173d956c680e43.par2",
		wantCode: 0,
	},
}

func TestIntegration(t *testing.T) {
	for name, tc := range integrationCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			for _, archive := range tc.archives {
				extractArchive(t, dir, archive)
			}

			var originals map[string][]byte
			if tc.setup != nil {
				originals = tc.setup(t, dir)
			}

			runDir := dir
			if tc.cmdDir != "" {
				runDir = filepath.Join(dir, tc.cmdDir)
			}

			got := runCLI(t, runDir, tc.subcmd, tc.par2file)
			if got != tc.wantCode {
				t.Errorf("exit code = %d, want %d", got, tc.wantCode)
			}

			if tc.check != nil && got == tc.wantCode {
				tc.check(t, dir, originals)
			}
		})
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func runCLI(t *testing.T, dir, subcmd, par2file string) int {
	t.Helper()
	cmd := exec.Command(cliPath, subcmd, par2file)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Logf("CLI output:\n%s", out)
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		t.Logf("CLI output (exit %d):\n%s", exitErr.ExitCode(), out)
		return exitErr.ExitCode()
	}
	t.Fatalf("CLI system error: %v", err)
	return -1
}

func extractArchive(t *testing.T, dir, archive string) {
	t.Helper()
	cmd := exec.Command("tar", "-xzf", filepath.Join(fixturesDir, archive))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("extract %s: %v\n%s", archive, err, out)
	}
}

// readFiles saves the contents of files (relative to dir) and returns them
// keyed by their relative path.
func readFiles(t *testing.T, dir string, relpaths ...string) map[string][]byte {
	t.Helper()
	m := make(map[string][]byte, len(relpaths))
	for _, p := range relpaths {
		data, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			t.Fatalf("readFiles %s: %v", p, err)
		}
		m[p] = slices.Clone(data)
	}
	return m
}

// assertFilesRestored verifies that each file in originals has been exactly
// restored after repair.
func assertFilesRestored(t *testing.T, dir string, originals map[string][]byte) {
	t.Helper()
	for p, want := range originals {
		got, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			t.Errorf("read restored %s: %v", p, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: restored %d bytes, want %d; content differs", p, len(got), len(want))
		}
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
}

func mustRemoveAll(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("removeAll %s: %v", path, err)
	}
}

func flipByteAt(t *testing.T, path string, offset int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("flipByteAt read %s: %v", path, err)
	}
	data[offset] ^= 0xFF
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("flipByteAt write %s: %v", path, err)
	}
}

func flipLastByte(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("flipLastByte read %s: %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("flipLastByte: %s is empty", path)
	}
	data[len(data)-1] ^= 0xFF
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("flipLastByte write %s: %v", path, err)
	}
}

func truncateFile(t *testing.T, path string, n int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("truncateFile read %s: %v", path, err)
	}
	if n > len(data) {
		n = len(data)
	}
	if err := os.WriteFile(path, data[:n], 0644); err != nil {
		t.Fatalf("truncateFile write %s: %v", path, err)
	}
}
