package par2

import (
	"errors"
	"hash/crc32"
)

type crc32Window struct {
	windowSize              int
	crcOldLeaderMaskedTable [256]uint32
}

// newCRC32Window computes rolling tables to calculate CRC32 in constant time
// O(1) regardless of the window size. Matches standard IEEE polynomial.
func newCRC32Window(windowSize int) (*crc32Window, error) {
	if windowSize < 4 {
		return nil, errors.New("window size too small for sliding calculation")
	}
	a := make([]byte, windowSize+1)
	crc0 := crc32.ChecksumIEEE(a)

	a[0] = 0xff
	a[4] = 0xff
	crcWindowMask := crc32.ChecksumIEEE(a)

	a[4] = 0
	var baseTable [8]uint32
	for i := range uint(8) {
		a[0] = byte(1 << i)
		baseTable[i] = crc32.ChecksumIEEE(a)
	}

	var maskedTable [256]uint32
	maskedTable[0] = crc0 ^ crcWindowMask
	for i := 1; i < 256; i++ {
		var crc uint32
		crcCount := 0
		for j := range uint(8) {
			if i&(1<<j) != 0 {
				crc ^= baseTable[j]
				crcCount++
			}
		}
		if crcCount%2 == 0 {
			crc ^= crc0
		}
		maskedTable[i] = crc ^ crcWindowMask
	}

	return &crc32Window{
		windowSize:              windowSize,
		crcOldLeaderMaskedTable: maskedTable,
	}, nil
}

// update rolls the window forward by 1 byte: drops oldLeader and appends newTrailer.
// Runs in constant time by using the precomputed IEEE tables.
func (w *crc32Window) update(crc uint32, oldLeader, newTrailer byte) uint32 {
	// Inline manual crc32.simpleUpdate for optimal performance inside the scanning hot path
	t := ^crc
	t = crc32.IEEETable[byte(t)^newTrailer] ^ (t >> 8)
	crcExtended := ^t

	return crcExtended ^ w.crcOldLeaderMaskedTable[oldLeader]
}
