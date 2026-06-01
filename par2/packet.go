package par2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

var expectedMagic = [8]byte{'P', 'A', 'R', '2', '\x00', 'P', 'K', 'T'}

// PacketType is a 16-byte packet type identifier.
type PacketType [16]byte

var (
	MainPacketType     = PacketType{'P', 'A', 'R', ' ', '2', '.', '0', '\x00', 'M', 'a', 'i', 'n'}
	FileDescPacketType = PacketType{'P', 'A', 'R', ' ', '2', '.', '0', '\x00', 'F', 'i', 'l', 'e', 'D', 'e', 's', 'c'}
	IFSCPacketType     = PacketType{'P', 'A', 'R', ' ', '2', '.', '0', '\x00', 'I', 'F', 'S', 'C'}
	RecoveryPacketType = PacketType{'P', 'A', 'R', ' ', '2', '.', '0', '\x00', 'R', 'e', 'c', 'v', 'S', 'l', 'i', 'c'}
)

// Header represents the standard 64-byte PAR2 packet header.
type Header struct {
	Magic         [8]byte
	Length        uint64
	Hash          [16]byte
	RecoverySetID [16]byte
	Type          PacketType
}

// FileID is a 16-byte MD5 hash identifying a file uniquely.
type FileID [16]byte

// FileIDLess compares two FileIDs according to the PAR2 specification.
// It performs a byte-by-byte comparison starting from the last byte (index 15)
// down to the first byte (index 0), as required by the spec's little-endian
// sorting requirement for FileIDs.
func FileIDLess(id1, id2 FileID) bool {
	for i := len(id1) - 1; i >= 0; i-- {
		if id1[i] < id2[i] {
			return true
		} else if id1[i] > id2[i] {
			return false
		}
	}
	return false
}

// mainPacket contains the recovery block size and lists of protected files.
type mainPacket struct {
	SliceByteCount int
	RecoverySet    []FileID
	NonRecoverySet []FileID
}

// FileDescPacket describes a protected data file's metadata.
type FileDescPacket struct {
	FileID       FileID
	Hash         [16]byte
	SixteenKHash [16]byte
	ByteCount    int
	Filename     string
}

// ChecksumPair maps a slice index to its expected MD5 and CRC32.
type ChecksumPair struct {
	MD5   [16]byte
	CRC32 [4]byte
}

// IFSCPacket maps a FileID to checksums for all its slices.
type IFSCPacket struct {
	FileID        FileID
	ChecksumPairs []ChecksumPair
}

// recoveryPacket contains a single Reed-Solomon parity block.
type recoveryPacket struct {
	Exponent uint16
	Data     []byte
}

// ReadHeader parses the standard 64-byte packet header from an io.Reader.
func ReadHeader(r io.Reader) (Header, error) {
	var h Header
	err := binary.Read(r, binary.LittleEndian, &h)
	if err != nil {
		return Header{}, err
	}
	if h.Magic != expectedMagic {
		return Header{}, errors.New("malformed PAR2 packet header: invalid magic")
	}
	if h.Length < 64 || h.Length%4 != 0 {
		return Header{}, errors.New("invalid PAR2 packet length")
	}
	return h, nil
}

// ComputePacketHash computes the MD5 hash of a packet body using streaming writes
// to avoid copying potentially multi-megabyte recovery packet bodies.
func ComputePacketHash(setID [16]byte, pType PacketType, body []byte) [16]byte {
	h := md5.New()
	h.Write(setID[:])
	h.Write(pType[:])
	h.Write(body)
	var result [16]byte
	copy(result[:], h.Sum(nil))
	return result
}

// NullTerminate slices the byte array at the first NULL byte.
func NullTerminate(bs []byte) []byte {
	for i, b := range bs {
		if b == '\x00' {
			return bs[:i]
		}
	}
	return bs
}

// DecodeNullPaddedASCIIString decodes ASCII string replacing non-ASCII characters safely.
func DecodeNullPaddedASCIIString(bs []byte) string {
	bs = NullTerminate(bs)
	var replaceBuf [4]byte
	n := utf8.EncodeRune(replaceBuf[:], unicode.ReplacementChar)

	outBytes := make([]byte, 0, len(bs))
	for _, b := range bs {
		if b <= unicode.MaxASCII {
			outBytes = append(outBytes, b)
		} else {
			outBytes = append(outBytes, replaceBuf[:n]...)
		}
	}
	return string(outBytes)
}

// DefangPath performs robust, cross-platform path sanitization to prevent directory traversal.
func DefangPath(filename string) (string, error) {
	// Normalize all backslashes to forward slashes for cross-platform check consistency
	normalized := strings.ReplaceAll(filename, "\\", "/")

	// Clean using path (always uses forward slash)
	cleaned := path.Clean(normalized)

	// Block absolute paths (both Unix "/" and Windows "C:/")
	if path.IsAbs(cleaned) {
		return "", errors.New("absolute path traversal attempt detected")
	}
	if len(cleaned) > 1 && cleaned[1] == ':' {
		return "", errors.New("windows drive absolute path traversal attempt detected")
	}

	// Block relative traversals escaping directory
	if strings.HasPrefix(cleaned, "..") {
		return "", errors.New("relative directory traversal attempt detected")
	}

	// Convert to host-native separators for actual disk operations
	return filepath.FromSlash(cleaned), nil
}

func computeFileID(sixteenKHash [16]byte, byteCount uint64, filenameBytes []byte) FileID {
	h := md5.New()
	h.Write(sixteenKHash[:])
	var byteCountBytes [8]byte
	binary.LittleEndian.PutUint64(byteCountBytes[:], byteCount)
	h.Write(byteCountBytes[:])
	h.Write(filenameBytes)
	var result FileID
	copy(result[:], h.Sum(nil))
	return result
}

// ParseMainPacket parses a Main Packet body.
func ParseMainPacket(body []byte) (*mainPacket, error) {
	if len(body) < 12 {
		return nil, errors.New("main packet too short")
	}
	sliceSize := binary.LittleEndian.Uint64(body[0:8])
	setCount := binary.LittleEndian.Uint32(body[8:12])

	maxInt := uint64(^uint(0) >> 1)
	if sliceSize == 0 || sliceSize%4 != 0 || sliceSize > maxInt {
		return nil, errors.New("invalid slice size in main packet")
	}

	buf := bytes.NewBuffer(body[12:])
	fileIDSize := 16
	if buf.Len()%fileIDSize != 0 {
		return nil, errors.New("invalid file ID list length")
	}
	fileIDs := make([]FileID, buf.Len()/fileIDSize)
	err := binary.Read(buf, binary.LittleEndian, fileIDs)
	if err != nil {
		return nil, err
	}

	if uint32(len(fileIDs)) < setCount {
		return nil, errors.New("insufficient file IDs for recovery set count")
	}

	recoverySet := fileIDs[:setCount]
	nonRecoverySet := fileIDs[setCount:]

	// Verify PAR2 spec sorted requirements
	if !slices.IsSortedFunc(recoverySet, func(a, b FileID) int {
		if FileIDLess(a, b) {
			return -1
		}
		if FileIDLess(b, a) {
			return 1
		}
		return 0
	}) {
		return nil, errors.New("recovery set file IDs are not sorted alphabetically")
	}

	return &mainPacket{
		SliceByteCount: int(sliceSize),
		RecoverySet:    recoverySet,
		NonRecoverySet: nonRecoverySet,
	}, nil
}

// ParseFileDescPacket parses a File Description Packet body.
func ParseFileDescPacket(body []byte) (*FileDescPacket, error) {
	if len(body) < 56 {
		return nil, errors.New("file description packet too short")
	}
	var fID FileID
	copy(fID[:], body[0:16])
	var hash [16]byte
	copy(hash[:], body[16:32])
	var hash16k [16]byte
	copy(hash16k[:], body[32:48])
	byteCount := binary.LittleEndian.Uint64(body[48:56])

	filenameBytes := body[56:]
	computed := computeFileID(hash16k, byteCount, NullTerminate(filenameBytes))
	if computed != fID {
		return nil, errors.New("file description ID mismatch")
	}

	if byteCount == 0 {
		return nil, nil // 0-byte files have no blocks; skip per PAR2 spec
	}

	filename := DecodeNullPaddedASCIIString(filenameBytes)
	defanged, err := DefangPath(filename)
	if err != nil {
		return nil, err
	}

	maxInt := uint64(^uint(0) >> 1)
	if byteCount > maxInt {
		return nil, errors.New("file byte count exceeds memory boundaries")
	}

	return &FileDescPacket{
		FileID:       fID,
		Hash:         hash,
		SixteenKHash: hash16k,
		ByteCount:    int(byteCount),
		Filename:     defanged,
	}, nil
}

// ParseIFSCPacket parses an IFSC Packet body.
func ParseIFSCPacket(body []byte) (*IFSCPacket, error) {
	if len(body) < 16 {
		return nil, errors.New("IFSC packet too short")
	}
	var fID FileID
	copy(fID[:], body[0:16])

	buf := bytes.NewBuffer(body[16:])
	pairSize := 20 // 16 byte MD5 + 4 byte CRC32
	if buf.Len() == 0 || buf.Len()%pairSize != 0 {
		return nil, errors.New("invalid checksum pair array length")
	}

	pairs := make([]ChecksumPair, buf.Len()/pairSize)
	err := binary.Read(buf, binary.LittleEndian, pairs)
	if err != nil {
		return nil, err
	}

	return &IFSCPacket{
		FileID:        fID,
		ChecksumPairs: pairs,
	}, nil
}

// ParseRecoveryPacket parses a Recovery Packet body.
func ParseRecoveryPacket(body []byte) (*recoveryPacket, error) {
	if len(body) < 4 || len(body)%4 != 0 {
		return nil, errors.New("invalid recovery packet body alignment")
	}
	exp := binary.LittleEndian.Uint32(body[0:4])
	if exp > 32767 {
		return nil, errors.New("recovery exponent exceeds safe engine limit (32767)")
	}

	// Copy parity data into its own allocation to avoid pinning the entire
	// file buffer in memory (the returned slice would otherwise alias body,
	// which aliases the full file read buffer).
	dataCopy := make([]byte, len(body[4:]))
	copy(dataCopy, body[4:])

	return &recoveryPacket{
		Exponent: uint16(exp),
		Data:     dataCopy,
	}, nil
}
