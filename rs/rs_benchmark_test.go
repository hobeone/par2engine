package rs

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
)

func BenchmarkGenerateParity(b *testing.B) {
	sizes := []int{16 * 1024, 1024 * 1024} // 16KB (PAR2 default slice), 1MB
	configs := []struct {
		data, parity int
	}{
		{10, 4},
		{100, 20},
	}

	for _, size := range sizes {
		for _, cfg := range configs {
			b.Run(fmt.Sprintf("size=%s/data=%d/parity=%d", formatSize(size), cfg.data, cfg.parity), func(b *testing.B) {
				coder, err := NewCoderPAR2Vandermonde(cfg.data, cfg.parity)
				if err != nil {
					b.Fatal(err)
				}

				data := make([][]byte, cfg.data)
				for i := range data {
					data[i] = make([]byte, size)
					_, _ = rand.Read(data[i])
				}

				ctx := context.Background()
				b.ResetTimer()
				b.ReportAllocs()
				b.SetBytes(int64(size * cfg.data))

				for b.Loop() {
					_, err := coder.GenerateParity(ctx, data, 0)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkReconstruct(b *testing.B) {
	sizes := []int{16 * 1024, 1024 * 1024} // 16KB, 1MB
	configs := []struct {
		data, parity int
		lost         int
	}{
		{10, 4, 1},
		{10, 4, 4},
		{100, 20, 5},
		{100, 20, 20},
	}

	for _, size := range sizes {
		for _, cfg := range configs {
			b.Run(fmt.Sprintf("size=%s/data=%d/parity=%d/lost=%d", formatSize(size), cfg.data, cfg.parity, cfg.lost), func(b *testing.B) {
				coder, err := NewCoderPAR2Vandermonde(cfg.data, cfg.parity)
				if err != nil {
					b.Fatal(err)
				}

				data := make([][]byte, cfg.data)
				for i := range data {
					data[i] = make([]byte, size)
					_, _ = rand.Read(data[i])
				}

				ctx := context.Background()
				parity, err := coder.GenerateParity(ctx, data, 0)
				if err != nil {
					b.Fatal(err)
				}

				b.ResetTimer()
				b.ReportAllocs()
				b.SetBytes(int64(size * cfg.lost))

				for b.Loop() {
					// Set up inputs (some data shards nil)
					dataCopy := make([][]byte, len(data))
					for i := range data {
						dataCopy[i] = make([]byte, size)
						copy(dataCopy[i], data[i])
					}
					// delete lost shards
					for i := 0; i < cfg.lost; i++ {
						dataCopy[i] = nil
					}

					parityCopy := make([][]byte, len(parity))
					for i := range parity {
						parityCopy[i] = make([]byte, size)
						copy(parityCopy[i], parity[i])
					}

					err := coder.Reconstruct(ctx, dataCopy, parityCopy, 0)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func formatSize(bytes int) string {
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%dM", bytes/(1024*1024))
	}
	if bytes >= 1024 {
		return fmt.Sprintf("%dK", bytes/1024)
	}
	return fmt.Sprintf("%dB", bytes)
}
