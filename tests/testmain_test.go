package tests

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const fixtureBaseURL = "https://raw.githubusercontent.com/parchive/par2cmdline/master/tests"

// allArchives lists every fixture archive downloaded from parchive/par2cmdline.
var allArchives = []string{
	"flatdata.tar.gz",
	"flatdata-par2files.tar.gz",
	"subdirdata.tar.gz",
	"subdirdata-par2files-unix.tar.gz",
	"subdirdata-par2files-win.tar.gz",
	"smallsubdirdata.tar.gz",
	"smallsubdirdata-par2files.tar.gz",
	"readbeyondeof.tar.gz",
	"par2-0.6.8-crash.tar.gz",
	"bug44.tar.gz",
	"bug128-parfiles.tar.gz",
}

// fixturesDir is set once in TestMain; all tests read it.
var fixturesDir string

// cliPath is the absolute path to the par2engine-cli binary, built in TestMain.
var cliPath string

func TestMain(m *testing.M) {
	dir, err := resolveFixtures()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: fixture setup failed: %v\n", err)
		os.Exit(1)
	}
	fixturesDir = dir

	if err := ensureCLI(); err != nil {
		fmt.Fprintf(os.Stderr, "integration: CLI build failed: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// resolveFixtures finds or downloads the canonical par2cmdline test archives.
// Resolution order:
//  1. tests/testdata/ (local cache from a previous run)
//  2. ../../par2cmdline/tests/ (sibling repo clone)
//  3. Download from GitHub into tests/testdata/
func resolveFixtures() (string, error) {
	localDir := "testdata"
	if archivesExist(localDir) {
		fmt.Printf("integration: using cached fixtures from %s\n", localDir)
		return localDir, nil
	}

	siblingDir, _ := filepath.Abs("../../par2cmdline/tests")
	if archivesExist(siblingDir) {
		fmt.Printf("integration: using sibling repo fixtures from %s\n", siblingDir)
		return siblingDir, nil
	}

	fmt.Println("integration: fixtures not found locally, downloading from github.com/parchive/par2cmdline")
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return "", fmt.Errorf("create testdata dir: %w", err)
	}
	for _, name := range allArchives {
		url := fixtureBaseURL + "/" + name
		dest := filepath.Join(localDir, name)
		if _, err := os.Stat(dest); err == nil {
			continue // already present from a partial previous run
		}
		fmt.Printf("integration: downloading %s ...\n", name)
		if err := downloadFile(url, dest); err != nil {
			_ = os.Remove(dest)
			return "", fmt.Errorf("download %s: %w", name, err)
		}
	}
	fmt.Println("integration: download complete")
	return localDir, nil
}

func archivesExist(dir string) bool {
	for _, name := range allArchives {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url) //nolint:noctx // fixture download, no deadline needed
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, resp.Body)
	return err
}

// ensureCLI builds the par2engine-cli binary if it is not already present.
func ensureCLI() error {
	abs, err := filepath.Abs("../par2engine-cli")
	if err != nil {
		return err
	}
	cliPath = abs
	if _, err := os.Stat(cliPath); err == nil {
		fmt.Printf("integration: using existing CLI at %s\n", cliPath)
		return nil
	}
	fmt.Println("integration: building par2engine-cli...")
	cmd := exec.Command("go", "build", "-o", cliPath, "../cmd/gopar")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v\n%s", err, out)
	}
	fmt.Println("integration: build complete")
	return nil
}
