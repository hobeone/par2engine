package par2

import (
	"context"
	"encoding/binary"
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

// makeRawPAR2Packet builds a correctly-formed PAR2 packet binary blob.
// body length must be a multiple of 4 (PAR2 spec alignment requirement).
func makeRawPAR2Packet(setID [16]byte, ptype PacketType, body []byte) []byte {
	const headerSize = 64
	total := headerSize + len(body)
	buf := make([]byte, total)
	copy(buf[0:8], "PAR2\x00PKT")
	binary.LittleEndian.PutUint64(buf[8:16], uint64(total))
	hash := ComputePacketHash(setID, ptype, body)
	copy(buf[16:32], hash[:])
	copy(buf[32:48], setID[:])
	copy(buf[48:64], ptype[:])
	copy(buf[64:], body)
	return buf
}

func newTestDecoder(t *testing.T, dir string) *Decoder {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	return &Decoder{
		root:          root,
		logger:        slog.Default(),
		maxFileSize:   10 * 1024 * 1024,
		maxPacketSize: 10 * 1024 * 1024,
	}
}

// TestStreamPAR2PacketsHashMismatch verifies that a packet with a corrupted
// hash field is rejected before the handler is invoked.
func TestStreamPAR2PacketsHashMismatch(t *testing.T) {
	dir := t.TempDir()
	var setID [16]byte
	setID[0] = 0x01

	pkt := makeRawPAR2Packet(setID, MainPacketType, make([]byte, 4))
	pkt[17] ^= 0xFF // corrupt one byte of the stored hash

	if err := os.WriteFile(filepath.Join(dir, "corrupt.par2"), pkt, 0644); err != nil {
		t.Fatal(err)
	}

	d := newTestDecoder(t, dir)
	defer func() { _ = d.Close() }()

	err := d.streamPAR2Packets(context.Background(), "corrupt.par2", func(Header, []byte) error {
		t.Error("handler must not be called for corrupted packet")
		return nil
	})
	if err == nil {
		t.Fatal("expected error for hash mismatch, got nil")
	}
}

// TestStreamPAR2PacketsFileSizeLimit verifies that files exceeding maxFileSize
// are rejected before any packet is parsed.
func TestStreamPAR2PacketsFileSizeLimit(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, 1024)
	if err := os.WriteFile(filepath.Join(dir, "big.par2"), data, 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := &Decoder{root: root, logger: slog.Default(), maxFileSize: 512, maxPacketSize: 10 * 1024 * 1024}
	defer func() { _ = d.Close() }()

	err = d.streamPAR2Packets(context.Background(), "big.par2", func(Header, []byte) error { return nil })
	if err == nil {
		t.Fatal("expected error for file exceeding size limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestStreamPAR2PacketsSetIDMismatch verifies that packets from a different
// recovery set are silently skipped — no error, and the handler is not called
// for the mismatching packet.
func TestStreamPAR2PacketsSetIDMismatch(t *testing.T) {
	dir := t.TempDir()
	var setID1, setID2 [16]byte
	setID1[0] = 0x01
	setID2[0] = 0x02

	var combined []byte
	combined = append(combined, makeRawPAR2Packet(setID1, MainPacketType, make([]byte, 4))...)
	combined = append(combined, makeRawPAR2Packet(setID2, MainPacketType, make([]byte, 4))...)
	if err := os.WriteFile(filepath.Join(dir, "mismatch.par2"), combined, 0644); err != nil {
		t.Fatal(err)
	}

	d := newTestDecoder(t, dir)
	defer func() { _ = d.Close() }()

	handled := 0
	err := d.streamPAR2Packets(context.Background(), "mismatch.par2", func(Header, []byte) error {
		handled++
		return nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if handled != 1 {
		t.Errorf("expected exactly 1 handled packet (set-ID-mismatch packet must be skipped), got %d", handled)
	}
}

func osIsPermissionOrNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "no such file") || strings.Contains(msg, "does not exist") || strings.Contains(msg, "outside root")
}
