package rs

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
)

func TestRSEndToEnd(t *testing.T) {
	dataShards := 4
	parityShards := 2
	coder, err := NewCoderPAR2Vandermonde(dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewCoder failed: %v", err)
	}

	shardSize := 64 // small shard size for fast tests

	// 1. Generate random data shards
	r := rand.New(rand.NewPCG(123, 456))
	originalData := make([][]byte, dataShards)
	for i := range originalData {
		originalData[i] = make([]byte, shardSize)
		for j := range originalData[i] {
			originalData[i][j] = byte(r.Uint32())
		}
	}

	// Clone data so we can corrupt it and compare later
	cloneShards := func(shards [][]byte) [][]byte {
		cloned := make([][]byte, len(shards))
		for i := range shards {
			if shards[i] != nil {
				cloned[i] = make([]byte, len(shards[i]))
				copy(cloned[i], shards[i])
			}
		}
		return cloned
	}

	ctx := context.Background()

	// 2. Encode to generate parity
	parity, err := coder.GenerateParity(ctx, originalData, 0)
	if err != nil {
		t.Fatalf("GenerateParity failed: %v", err)
	}
	if len(parity) != parityShards {
		t.Fatalf("got %d parity shards, want %d", len(parity), parityShards)
	}

	t.Run("loss_two_data_shards", func(t *testing.T) {
		dataCopy := cloneShards(originalData)
		parityCopy := cloneShards(parity)

		// Corrupt data: lose shard 1 and 3
		dataCopy[1] = nil
		dataCopy[3] = nil

		err := coder.Reconstruct(ctx, dataCopy, parityCopy, 0)
		if err != nil {
			t.Fatalf("Reconstruct failed: %v", err)
		}

		// Check bitwise identical
		for i := range originalData {
			if !bytes.Equal(dataCopy[i], originalData[i]) {
				t.Fatalf("shard %d mismatch after reconstruction", i)
			}
		}
	})

	t.Run("loss_one_data_one_parity", func(t *testing.T) {
		dataCopy := cloneShards(originalData)
		parityCopy := cloneShards(parity)

		// Corrupt: lose data shard 2 and parity shard 0
		dataCopy[2] = nil
		parityCopy[0] = nil

		err := coder.Reconstruct(ctx, dataCopy, parityCopy, 0)
		if err != nil {
			t.Fatalf("Reconstruct failed: %v", err)
		}

		// Check bitwise identical for data
		for i := range originalData {
			if !bytes.Equal(dataCopy[i], originalData[i]) {
				t.Fatalf("shard %d mismatch after reconstruction", i)
			}
		}
	})

	t.Run("mismatched_lengths", func(t *testing.T) {
		dataCopy := cloneShards(originalData)
		parityCopy := cloneShards(parity)

		// Make shard 1 have different length
		dataCopy[1] = make([]byte, shardSize+1)

		err := coder.Reconstruct(ctx, dataCopy, parityCopy, 0)
		if err == nil || err.Error() != "mismatched shard lengths" {
			t.Fatalf("got err = %v, want 'mismatched shard lengths'", err)
		}

		_, err = coder.GenerateParity(ctx, dataCopy, 0)
		if err == nil || err.Error() != "mismatched shard lengths" {
			t.Fatalf("got err = %v, want 'mismatched shard lengths'", err)
		}
	})

	t.Run("not_enough_parity", func(t *testing.T) {
		dataCopy := cloneShards(originalData)
		parityCopy := cloneShards(parity)

		// Corrupt: lose data shard 0, 1, 2 (needs 3, but we only have 2 parity shards)
		dataCopy[0] = nil
		dataCopy[1] = nil
		dataCopy[2] = nil

		err := coder.Reconstruct(ctx, dataCopy, parityCopy, 0)
		if !errors.Is(err, ErrNotEnoughParity) {
			t.Fatalf("got err = %v, want ErrNotEnoughParity", err)
		}
	})
}

func TestRSContextCancellation(t *testing.T) {
	dataShards := 4
	parityShards := 2
	coder, err := NewCoderPAR2Vandermonde(dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewCoder failed: %v", err)
	}

	// Use a huge shard size to ensure multiplication takes enough time to cancel
	shardSize := 1024 * 1024 // 1MB Shards

	r := rand.New(rand.NewPCG(42, 42))
	data := make([][]byte, dataShards)
	for i := range data {
		data[i] = make([]byte, shardSize)
		for j := range data[i] {
			data[i][j] = byte(r.Uint32())
		}
	}

	ctx := context.Background()
	parity, err := coder.GenerateParity(ctx, data, 1)
	if err != nil {
		t.Fatalf("GenerateParity failed: %v", err)
	}

	// Corrupt shards
	data[1] = nil
	data[2] = nil

	// Reconstruct with cancelled context
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // cancel immediately

	err = coder.Reconstruct(cancelCtx, data, parity, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got err = %v, want context.Canceled", err)
	}
}

func TestRSInputValidation(t *testing.T) {
	coder, err := NewCoderPAR2Vandermonde(4, 2)
	if err != nil {
		t.Fatalf("NewCoder failed: %v", err)
	}

	ctx := context.Background()
	validData := make([][]byte, 4)
	for i := range validData {
		validData[i] = make([]byte, 64)
	}
	validParity := make([][]byte, 2)
	for i := range validParity {
		validParity[i] = make([]byte, 64)
	}

	t.Run("invalid_data_shard_count_too_few", func(t *testing.T) {
		tooFewData := make([][]byte, 3)
		err := coder.Reconstruct(ctx, tooFewData, validParity, 0)
		if !errors.Is(err, ErrInvalidDataShardCount) {
			t.Fatalf("got err = %v, want ErrInvalidDataShardCount", err)
		}
	})

	t.Run("invalid_data_shard_count_too_many", func(t *testing.T) {
		tooManyData := make([][]byte, 5)
		err := coder.Reconstruct(ctx, tooManyData, validParity, 0)
		if !errors.Is(err, ErrInvalidDataShardCount) {
			t.Fatalf("got err = %v, want ErrInvalidDataShardCount", err)
		}
	})

	t.Run("invalid_parity_shard_count_too_many", func(t *testing.T) {
		tooManyParity := make([][]byte, 3)
		err := coder.Reconstruct(ctx, validData, tooManyParity, 0)
		if !errors.Is(err, ErrInvalidParityShardCount) {
			t.Fatalf("got err = %v, want ErrInvalidParityShardCount", err)
		}
	})
}

func TestNewCoderValidation(t *testing.T) {
	t.Run("data_shards_zero", func(t *testing.T) {
		_, err := NewCoderPAR2Vandermonde(0, 2)
		if err == nil || err.Error() != "invalid shard counts" {
			t.Fatalf("expected 'invalid shard counts', got: %v", err)
		}
	})
	t.Run("parity_shards_zero", func(t *testing.T) {
		_, err := NewCoderPAR2Vandermonde(4, 0)
		if err == nil || err.Error() != "invalid shard counts" {
			t.Fatalf("expected 'invalid shard counts', got: %v", err)
		}
	})
	t.Run("too_many_data_shards", func(t *testing.T) {
		// generators limit is 32768
		_, err := NewCoderPAR2Vandermonde(32769, 2)
		if err == nil || err.Error() != "too many data shards for generator limit" {
			t.Fatalf("expected 'too many data shards for generator limit', got: %v", err)
		}
	})
	t.Run("too_many_parity_shards", func(t *testing.T) {
		_, err := NewCoderPAR2Vandermonde(4, 65536)
		if err == nil || err.Error() != "too many parity shards for GF(2^16)" {
			t.Fatalf("expected 'too many parity shards for GF(2^16)', got: %v", err)
		}
	})
}

func TestRSParallelBoundaries(t *testing.T) {
	coder, err := NewCoderPAR2Vandermonde(2, 2)
	if err != nil {
		t.Fatal(err)
	}

	r := rand.New(rand.NewPCG(42, 42))

	ctx := context.Background()

	// Test various sizes that exercise the parallel slicing logic and SIMD alignment (16-byte boundary).
	sizes := []int{16, 20, 32, 34, 48, 64, 80, 128, 256}
	for _, size := range sizes {
		data := make([][]byte, 2)
		for i := range data {
			data[i] = make([]byte, size)
			for j := range data[i] {
				data[i][j] = byte(r.Uint32())
			}
		}
		dataOrig := [][]byte{slices.Clone(data[0]), slices.Clone(data[1])}

		parity, err := coder.GenerateParity(ctx, data, 4) // force parallel execution
		if err != nil {
			t.Fatalf("size=%d parallel GenerateParity failed: %v", size, err)
		}

		data[0] = nil                                 // lose first shard
		err = coder.Reconstruct(ctx, data, parity, 4) // parallel Reconstruct
		if err != nil {
			t.Fatalf("size=%d parallel Reconstruct failed: %v", size, err)
		}

		if !bytes.Equal(data[0], dataOrig[0]) {
			t.Fatalf("size=%d parallel Reconstruct data mismatch", size)
		}
	}
}
