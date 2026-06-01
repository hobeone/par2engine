package par2

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

func newCRCLookupTable(checksumMap map[uint32][]checksumLocation) *crcLookupTable {
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
