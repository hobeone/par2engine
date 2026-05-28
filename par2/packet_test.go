package par2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"strings"
	"testing"
)

func TestDefangPath(t *testing.T) {
	testCases := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{"safe relative", "foo/bar.rar", "foo/bar.rar", false},
		{"safe flat", "file.dat", "file.dat", false},
		{"absolute unix", "/etc/passwd", "", true},
		{"traversal relative", "../../passwd", "", true},
		{"traversal hidden", "foo/../../../passwd", "", true},
		{"absolute windows", `C:\windows\system32`, "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DefangPath(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DefangPath(%q) err = %v, wantErr %v", tc.path, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("DefangPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestParseMainPacket(t *testing.T) {
	// Valid Main Packet: slice size 2048, setCount 2, two sorted FileIDs
	id1 := FileID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	id2 := FileID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	body := make([]byte, 12+32)
	binary.LittleEndian.PutUint64(body[0:8], 2048)
	binary.LittleEndian.PutUint32(body[8:12], 2)
	copy(body[12:28], id1[:])
	copy(body[28:44], id2[:])

	p, err := ParseMainPacket(body)
	if err != nil {
		t.Fatalf("ParseMainPacket failed: %v", err)
	}
	if p.SliceByteCount != 2048 {
		t.Fatalf("got SliceByteCount %d, want 2048", p.SliceByteCount)
	}
	if len(p.RecoverySet) != 2 {
		t.Fatalf("got recovery set size %d, want 2", len(p.RecoverySet))
	}

	// Test unsorted FileIDs: id2 before id1
	binary.LittleEndian.PutUint32(body[8:12], 2)
	copy(body[12:28], id2[:])
	copy(body[28:44], id1[:])

	_, err = ParseMainPacket(body)
	if err == nil {
		t.Fatal("expected error for unsorted FileIDs, got nil")
	}
}

func TestParseFileDescPacket(t *testing.T) {
	filename := "test.bin"
	filenameBytes := append([]byte(filename), 0, 0, 0, 0)[:12] // null padded to multiple of 4
	byteCount := uint64(1024)
	hash16k := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	fID := computeFileID(hash16k, byteCount, NullTerminate(filenameBytes))

	body := make([]byte, 56+len(filenameBytes))
	copy(body[0:16], fID[:])
	// hash at 16:32 (leave zero for simplicity)
	copy(body[32:48], hash16k[:])
	binary.LittleEndian.PutUint64(body[48:56], byteCount)
	copy(body[56:], filenameBytes)

	p, err := ParseFileDescPacket(body)
	if err != nil {
		t.Fatalf("ParseFileDescPacket failed: %v", err)
	}
	if p.Filename != "test.bin" {
		t.Fatalf("got Filename %q, want %q", p.Filename, "test.bin")
	}
	if p.ByteCount != 1024 {
		t.Fatalf("got ByteCount %d, want 1024", p.ByteCount)
	}

	// Test absolute path traversal attempt inside description packet
	badFilename := "/etc/passwd"
	badFilenameBytes := append([]byte(badFilename), 0, 0, 0, 0)[:16]
	badFID := computeFileID(hash16k, byteCount, NullTerminate(badFilenameBytes))

	badBody := make([]byte, 56+len(badFilenameBytes))
	copy(badBody[0:16], badFID[:])
	copy(badBody[32:48], hash16k[:])
	binary.LittleEndian.PutUint64(badBody[48:56], byteCount)
	copy(badBody[56:], badFilenameBytes)

	_, err = ParseFileDescPacket(badBody)
	if err == nil {
		t.Fatal("expected path traversal block error, got nil")
	}
}

func TestParseIFSCPacket(t *testing.T) {
	fID := FileID{1, 2, 3, 4}
	pair := ChecksumPair{
		MD5:   [16]byte{0xa},
		CRC32: [4]byte{0x1, 0x2, 0x3, 0x4},
	}

	body := make([]byte, 16+20)
	copy(body[0:16], fID[:])
	copy(body[16:32], pair.MD5[:])
	copy(body[32:36], pair.CRC32[:])

	p, err := ParseIFSCPacket(body)
	if err != nil {
		t.Fatalf("ParseIFSCPacket failed: %v", err)
	}
	if p.FileID != fID {
		t.Fatalf("got FileID %v, want %v", p.FileID, fID)
	}
	if len(p.ChecksumPairs) != 1 {
		t.Fatalf("got %d checksum pairs, want 1", len(p.ChecksumPairs))
	}
}

func TestParseRecoveryPacket(t *testing.T) {
	body := make([]byte, 12)
	binary.LittleEndian.PutUint32(body[0:4], 5)
	copy(body[4:], []byte{0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2})

	p, err := ParseRecoveryPacket(body)
	if err != nil {
		t.Fatalf("ParseRecoveryPacket failed: %v", err)
	}
	if p.Exponent != 5 {
		t.Fatalf("got Exponent %d, want 5", p.Exponent)
	}
	if len(p.Data) != 8 {
		t.Fatalf("got Data size %d, want 8", len(p.Data))
	}

	// Test exponent exceeding limit
	binary.LittleEndian.PutUint32(body[0:4], 40000)
	_, err = ParseRecoveryPacket(body)
	if err == nil || err.Error() != "recovery exponent exceeds safe engine limit (32767)" {
		t.Fatalf("got err = %v, want 'recovery exponent exceeds safe engine limit (32767)'", err)
	}
}
func TestReadHeader(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h := Header{
			Magic:  expectedMagic,
			Length: 64,
		}
		var buf [64]byte
		copy(buf[0:8], expectedMagic[:])
		binary.LittleEndian.PutUint64(buf[8:16], 64)

		got, err := ReadHeader(bytes.NewReader(buf[:]))
		if err != nil {
			t.Fatalf("ReadHeader failed: %v", err)
		}
		if got.Magic != h.Magic {
			t.Errorf("got magic %v, want %v", got.Magic, h.Magic)
		}
	})

	t.Run("invalid_magic", func(t *testing.T) {
		var buf [64]byte
		copy(buf[0:8], "BADMAGIC")
		_, err := ReadHeader(bytes.NewReader(buf[:]))
		if err == nil || !strings.Contains(err.Error(), "invalid magic") {
			t.Fatalf("got err = %v, want invalid magic error", err)
		}
	})

	t.Run("invalid_length", func(t *testing.T) {
		var buf [64]byte
		copy(buf[0:8], expectedMagic[:])
		binary.LittleEndian.PutUint64(buf[8:16], 63) // too short
		_, err := ReadHeader(bytes.NewReader(buf[:]))
		if err == nil || !strings.Contains(err.Error(), "invalid PAR2 packet length") {
			t.Fatalf("got err = %v, want invalid length error", err)
		}
	})
}

func TestComputePacketHash(t *testing.T) {
	data := []byte("hello world")
	setID := [16]byte{1, 2, 3}
	pType := PacketType{1}

	hash := ComputePacketHash(setID, pType, data)

	// Manually compute MD5 of body
	h := md5.New()
	h.Write(setID[:])
	h.Write(pType[:])
	h.Write(data)
	expected := h.Sum(nil)
	if !bytes.Equal(hash[:], expected) {
		t.Errorf("got hash %x, want %x", hash, expected)
	}
}

func TestShardCounts_BlocksNeeded(t *testing.T) {
	testCases := []struct {
		name     string
		unusable int
		usable   int
		want     int
	}{
		{"no_repair", 0, 10, 0},
		{"possible_repair", 5, 5, 0},
		{"possible_repair_surplus", 5, 10, 0},
		{"needed_repair", 10, 5, 5},
		{"needed_repair_none", 10, 0, 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sc := ShardCounts{
				UnusableDataShardCount: tc.unusable,
				UsableParityShardCount: tc.usable,
			}
			if got := sc.BlocksNeeded(); got != tc.want {
				t.Errorf("BlocksNeeded() = %d, want %d", got, tc.want)
			}
		})
	}
}
