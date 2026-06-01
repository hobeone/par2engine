package par2

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecoderSandboxing(t *testing.T) {
	// Verify that os.Root sandboxing correctly throws an error if we try to escape
	dir := t.TempDir()

	// Create a decoder inside target directory
	dummyIndex := filepath.Join(dir, "dummy.par2")
	if err := os.WriteFile(dummyIndex, []byte("PAR2\x00PKT"), 0644); err != nil {
		t.Fatalf("failed to write dummy index: %v", err)
	}

	d := &Decoder{
		numGoroutines: 1,
		memoryLimit:   1024,
		logger:        slog.Default(),
		fileChecksums: make(map[FileID]*IFSCPacket),
		parityShards:  make(map[uint16][]byte),
		fileIntegrity: make(map[FileID]*fileIntegrityState),
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot failed: %v", err)
	}
	d.root = root
	defer func() { _ = d.Close() }()

	// Attempt to open a file outside the root (e.g., absolute path on Unix, or drive path on Windows, or relative traversal)
	_, err = d.root.Open("../escaped.dat")
	if err == nil {
		t.Fatal("expected directory traversal block error from os.Root, got nil")
	}
	if !osIsPermissionOrNotExist(err) {
		t.Logf("Got expected OS-enforced sandboxing block error: %v", err)
	}
}

func osIsPermissionOrNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "no such file") || strings.Contains(msg, "does not exist") || strings.Contains(msg, "outside root")
}
