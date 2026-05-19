package par2

import (
	"encoding/binary"
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
}

