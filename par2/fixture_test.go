package par2

import (
	"context"
	"flag"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// updateFixtures regenerates the PAR2 sets under testdata/fixtures with the
// reference par2cmdline binary:
//
//	go test ./par2/ -run TestPar2Fixtures -update-fixtures
var updateFixtures = flag.Bool("update-fixtures", false, "regenerate testdata/fixtures with par2cmdline")

// fixtureFile is one protected file of a fixture: its slash-separated path
// relative to the set's directory, and its contents.
type fixtureFile struct {
	path string
	data []byte
}

// par2Fixture is a PAR2 set created by par2cmdline and checked in, so the
// tests that cross-check this engine against the reference implementation
// run everywhere, not only where par2cmdline is installed. Only the .par2
// files are checked in; the protected files are regenerated from fixed seeds
// by files, which is the single definition both the tests and
// -update-fixtures use.
type par2Fixture struct {
	name      string // directory under testdata/fixtures
	blockSize int
	recovery  int
	files     func() []fixtureFile
}

// seededFiles returns files of the given sizes filled from one PCG stream,
// in order, matching how the tests generated their data before fixtures.
func seededFiles(seed uint64, files ...fixtureFile) []fixtureFile {
	r := rand.New(rand.NewPCG(seed, seed))
	for i := range files {
		for j := range files[i].data {
			files[i].data[j] = byte(r.Uint32())
		}
	}
	return files
}

func sized(path string, size int) fixtureFile { return fixtureFile{path, make([]byte, size)} }

// allFixtures holds every fixture, in declaration order: each is added by
// fixture as it is declared, so TestPar2Fixtures and -update-fixtures cannot
// miss one.
var allFixtures []par2Fixture

func fixture(fx par2Fixture) par2Fixture {
	allFixtures = append(allFixtures, fx)
	return fx
}

// fileStateSliceSize is the block size of the filestate fixtures.
const fileStateSliceSize = 16384

var (
	fixtureTwoFiles = fixture(par2Fixture{"two_files", 16384, 4, func() []fixtureFile {
		return seededFiles(42, sized("file1.dat", 128*1024), sized("file2.dat", 256*1024))
	}})
	// One 64 KB file named correct.dat, for the candidate and rename tests.
	fixtureCorrectDat = fixture(par2Fixture{"correct_dat", 16384, 4, func() []fixtureFile {
		return seededFiles(77, sized("correct.dat", 64*1024))
	}})
	fixtureRenameNested = fixture(par2Fixture{"rename_nested", 1024, 1, func() []fixtureFile {
		return seededFiles(88, sized("nested/dir/correct.dat", 1024))
	}})
	// A 40 MB file crosses the 32 MB scanChunkSize boundary. Its test only
	// verifies, so the set has no recovery blocks and only the index is
	// checked in.
	fixtureMultiChunk = fixture(par2Fixture{"multichunk", 10 * 1024 * 1024, 0, func() []fixtureFile {
		return seededFiles(99, sized("bigfile.dat", 40*1024*1024))
	}})
	fixtureFileState           = fixture(fileStateFixture("filestate", "f.dat", 4))
	fixtureFileStateNoRecovery = fixture(fileStateFixture("filestate_no_recovery", "f.dat", 0))
	fixtureFileStateNested     = fixture(fileStateFixture("filestate_nested", "sub/dir/f.dat", 4))
)

// fileStateFixture is a 16-block file in 16 KB blocks with recovery blocks.
func fileStateFixture(name, path string, recovery int) par2Fixture {
	return par2Fixture{name, fileStateSliceSize, recovery, func() []fixtureFile {
		return seededFiles(7, sized(path, 16*fileStateSliceSize))
	}}
}

func (fx par2Fixture) dir() string { return filepath.Join("testdata", "fixtures", fx.name) }

// load writes the fixture's protected files and copies its checked-in .par2
// files into a new temporary directory. It returns that directory, the path
// of the index file, and each protected file's contents keyed by its path.
func (fx par2Fixture) load(t testing.TB) (dir, par2Path string, data map[string][]byte) {
	t.Helper()
	dir = t.TempDir()
	data = make(map[string][]byte)
	for _, f := range fx.files() {
		writeTestFile(t, filepath.Join(dir, filepath.FromSlash(f.path)), f.data)
		data[f.path] = f.data
	}
	if _, err := os.Stat(filepath.Join(fx.dir(), "set.par2")); err != nil {
		t.Fatalf("fixture %s: %v; run: go test ./par2/ -run TestPar2Fixtures -update-fixtures", fx.name, err)
	}
	if err := os.CopyFS(dir, os.DirFS(fx.dir())); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(dir, "set.par2"), data
}

// generate creates the fixture's PAR2 set with par2cmdline in a new temporary
// directory and returns the .par2 files it produced, keyed by base name.
func (fx par2Fixture) generate(t *testing.T) map[string][]byte {
	t.Helper()
	dir := t.TempDir()
	args := []string{"c", "-q", "-q", "-s" + strconv.Itoa(fx.blockSize), "-c" + strconv.Itoa(fx.recovery), "set.par2"}
	for _, f := range fx.files() {
		writeTestFile(t, filepath.Join(dir, filepath.FromSlash(f.path)), f.data)
		args = append(args, filepath.FromSlash(f.path))
	}
	cmd := exec.Command("par2", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("par2 create %s: %v\n%s", fx.name, err, out)
	}
	sets, err := filepath.Glob(filepath.Join(dir, "*.par2"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte)
	for _, p := range sets {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(p)] = b
	}
	return out
}

// TestPar2Fixtures checks that every checked-in fixture matches its
// definition: loaded fresh, each set verifies with every block present, no
// repair needed, and the defined number of recovery blocks. A change to a
// fixture's data, names, block size or recovery count without regenerating
// its .par2 files fails here. It compares what the set describes rather than
// par2cmdline's exact bytes, which carry its version and so would change with
// the installed binary.
//
// With -update-fixtures it first rewrites every set with par2cmdline.
func TestPar2Fixtures(t *testing.T) {
	if *updateFixtures {
		if _, err := exec.LookPath("par2"); err != nil {
			t.Fatal("par2cmdline is required to regenerate fixtures")
		}
	}
	for _, fx := range allFixtures {
		t.Run(fx.name, func(t *testing.T) {
			if *updateFixtures {
				if err := os.RemoveAll(fx.dir()); err != nil {
					t.Fatal(err)
				}
				for name, b := range fx.generate(t) {
					writeTestFile(t, filepath.Join(fx.dir(), name), b)
				}
			}

			_, par2Path, _ := fx.load(t)
			ctx := context.Background()
			d, err := NewDecoder(ctx, par2Path, DecoderOptions{})
			if err != nil {
				t.Fatalf("NewDecoder: %v", err)
			}
			defer func() { _ = d.Close() }()
			if err := d.VerifyScans(ctx, nil); err != nil {
				t.Fatalf("VerifyScans: %v", err)
			}
			counts := d.ShardCounts()
			if counts.RepairNeeded() || counts.UsableParityShardCount != fx.recovery || d.sliceByteCount != fx.blockSize {
				t.Errorf("fixture does not match its definition (counts %+v, block size %d; want %d recovery blocks, block size %d, no repair); run: go test ./par2/ -run TestPar2Fixtures -update-fixtures",
					counts, d.sliceByteCount, fx.recovery, fx.blockSize)
			}
		})
	}
}
