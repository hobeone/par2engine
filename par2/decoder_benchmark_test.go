package par2

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func BenchmarkVerifyScans(b *testing.B) {
	_, ok := hasPar2()
	if !ok {
		b.Skip("par2 binary not found in PATH; skipping benchmark")
	}

	sizes := []int{10 * 1024 * 1024, 50 * 1024 * 1024} // 10MB, 50MB

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size=%s", formatSize(size)), func(b *testing.B) {
			dir := b.TempDir()
			inputFile1 := filepath.Join(dir, "file1.dat")
			inputFile2 := filepath.Join(dir, "file2.dat")

			r := rand.New(rand.NewPCG(42, 42))
			generateData := func(size int) []byte {
				data := make([]byte, size)
				for i := range data {
					data[i] = byte(r.Uint32())
				}
				return data
			}

			// Split size into two files
			data1 := generateData(size / 3)
			data2 := generateData(size - len(data1))

			if err := os.WriteFile(inputFile1, data1, 0644); err != nil {
				b.Fatalf("failed to write file1: %v", err)
			}
			if err := os.WriteFile(inputFile2, data2, 0644); err != nil {
				b.Fatalf("failed to write file2: %v", err)
			}

			// Create parity files
			par2Path := filepath.Join(dir, "set.par2")
			createCmd := exec.Command("par2", "c", "-s262144", "-c4", par2Path, inputFile1, inputFile2) // 256KB slice size
			createCmd.Dir = dir
			out, err := createCmd.CombinedOutput()
			if err != nil {
				b.Fatalf("failed to create par2 set: %v\n%s", err, out)
			}

			ctx := context.Background()
			
			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(size))

			for b.Loop() {
				d, err := NewDecoder(ctx, par2Path, DecoderOptions{})
				if err != nil {
					b.Fatal(err)
				}
				err = d.VerifyScans(ctx, nil)
				if err != nil {
					b.Fatal(err)
				}
				_ = d.Close()
			}
		})
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
