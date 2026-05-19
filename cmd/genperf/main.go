package main

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: go run ./cmd/genperf <target_directory>\n")
		os.Exit(1)
	}

	dir := os.Args[1]
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create directory: %v\n", err)
		os.Exit(1)
	}

	// 1. Generate 18GB large-file.dat with 100% unique 4MB blocks
	largeFilePath := filepath.Join(dir, "large-file.dat")
	fmt.Printf("Generating 18GB unique-block dataset at %s...\n", largeFilePath)

	r := rand.New(rand.NewPCG(42, 42))
	
	// Allocate 4MB block buffer
	const blockSize = 4 * 1024 * 1024
	block := make([]byte, blockSize)
	for i := range block {
		block[i] = byte(r.Uint32())
	}

	largeFile, err := os.OpenFile(largeFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating large file: %v\n", err)
		os.Exit(1)
	}

	startLarge := time.Now()
	// 4608 blocks = 18 GB
	for j := uint64(0); j < 4608; j++ {
		// Write the block index inside the first 8 bytes to guarantee block uniqueness!
		binary.LittleEndian.PutUint64(block[:8], j)
		_, err = largeFile.Write(block)
		if err != nil {
			largeFile.Close()
			fmt.Fprintf(os.Stderr, "Error writing block %d: %v\n", j, err)
			os.Exit(1)
		}
	}
	largeFile.Close()
	fmt.Printf("Successfully generated 18GB unique-block file in %s!\n", time.Since(startLarge))

	// 2. Generate 10 small files (1-4MB)
	fmt.Println("Generating 10 small files...")
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("small-%d.dat", i)
		size := (1 + rand.IntN(4)) * 1024 * 1024
		data := make([]byte, size)
		for j := range data {
			data[j] = byte(r.Uint32())
		}
		err = os.WriteFile(filepath.Join(dir, name), data, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing small file %s: %v\n", name, err)
			os.Exit(1)
		}
	}

	fmt.Println("\nDataset generation completed successfully!")
	fmt.Printf("Now generate the canonical PAR2 recovery set using:\n")
	fmt.Printf("  par2 c -s4194304 -c230 %s/set.par2 %s/large-file.dat %s/small-*.dat\n\n", dir, dir, dir)
}
