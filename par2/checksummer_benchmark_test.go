package par2

import (
	"hash/crc32"
	"testing"
)

func BenchmarkCRC32Rolling(b *testing.B) {
	windowSize := 16384 // PAR2 standard block size
	w, err := newCRC32Window(windowSize)
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, windowSize+1000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	currentCRC := crc32.ChecksumIEEE(data[:windowSize])

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		crc := currentCRC
		for i := 0; i < 500; i++ {
			oldByte := data[i]
			newByte := data[i+windowSize]
			crc = w.update(crc, oldByte, newByte)
		}
	}
}

func BenchmarkCRC32FullIEEE(b *testing.B) {
	windowSize := 16384 // PAR2 standard block size
	data := make([]byte, windowSize+1000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		for i := 0; i < 500; i++ {
			_ = crc32.ChecksumIEEE(data[i : i+windowSize])
		}
	}
}
