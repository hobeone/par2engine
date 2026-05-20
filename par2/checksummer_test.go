package par2

import (
	"hash/crc32"
	"testing"
)

func TestCRC32Window(t *testing.T) {
	windowSize := 16384
	w, err := newCRC32Window(windowSize)
	if err != nil {
		t.Fatalf("failed to create window: %v", err)
	}

	data := make([]byte, windowSize+100)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// 1. Initial window CRC
	currentCRC := crc32.ChecksumIEEE(data[:windowSize])

	// 2. Slide window and verify against full ChecksumIEEE
	for i := range 50 {
		oldByte := data[i]
		newByte := data[i+windowSize]
		currentCRC = w.update(currentCRC, oldByte, newByte)

		expectedCRC := crc32.ChecksumIEEE(data[i+1 : i+1+windowSize])
		if currentCRC != expectedCRC {
			t.Errorf("step %d: rolling CRC %08x != expected %08x", i, currentCRC, expectedCRC)
		}
	}
}

func TestCRC32WindowSmall(t *testing.T) {
	_, err := newCRC32Window(3)
	if err == nil {
		t.Error("expected error for window size < 4")
	}
}
