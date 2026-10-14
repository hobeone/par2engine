package par2

import (
	"slices"
	"sync/atomic"
)

// crcTableEntry is one slot in the open-addressing CRC lookup table.
type crcTableEntry struct {
	crc   uint32
	valid bool
	locs  []checksumLocation
}

// crcLookupTable is a hand-rolled open-addressing hash table mapping CRC32
// values to their checksum locations. It avoids the map[uint32]... allocation
// overhead in the sliding-window scan hot path.
type crcLookupTable struct {
	mask  uint32
	table []crcTableEntry
}

// newCRCLookupTable builds the table from checksumMap, giving each location a
// reported flag of its own, all cleared. Each block of the set appears at
// exactly one location, so its flag is its own.
func newCRCLookupTable(checksumMap map[uint32][]checksumLocation) *crcLookupTable {
	numLocs := 0
	for _, locs := range checksumMap {
		numLocs += len(locs)
	}
	flags := make([]atomic.Bool, numLocs)

	numEntries := len(checksumMap)
	size := 16
	for size < numEntries*4 {
		size *= 2
	}

	t := &crcLookupTable{
		mask:  uint32(size - 1),
		table: make([]crcTableEntry, size),
	}

	for crc, locs := range checksumMap {
		locs = slices.Clone(locs)
		for i := range locs {
			locs[i].reported = &flags[0]
			flags = flags[1:]
		}
		idx := crc & t.mask
		for {
			if !t.table[idx].valid {
				t.table[idx] = crcTableEntry{
					crc:   crc,
					valid: true,
					locs:  locs,
				}
				break
			}
			idx = (idx + 1) & t.mask
		}
	}
	return t
}

// Lookup returns the locations whose block has CRC32 crc.
func (t *crcLookupTable) Lookup(crc uint32) ([]checksumLocation, bool) {
	idx := crc & t.mask
	for {
		entry := &t.table[idx]
		if !entry.valid {
			return nil, false
		}
		if entry.crc == crc {
			return entry.locs, true
		}
		idx = (idx + 1) & t.mask
	}
}
