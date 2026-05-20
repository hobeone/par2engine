package rs

import (
	"context"
	"errors"
	"runtime"
	"sync"

	"github.com/hobeone/par2engine/gf16"
)

// DefaultNumGoroutines returns the number of physical CPU cores as default,
// which is optimal for CPU-intensive SIMD workloads.
func DefaultNumGoroutines() int {
	return runtime.NumCPU()
}

// Coder represents a Reed-Solomon encoder/decoder for PAR2 Vandermonde matrices.
type Coder struct {
	dataShards   int
	parityShards int
	parityMatrix Matrix
}

var generators []gf16.T

func init() {
	// Generate PAR2 generator elements (primitive elements of order 65535).
	// 65535 = 3 * 5 * 17 * 257. We check exponents relatively prime to 65535.
	for i := range 1 << 16 {
		if i%3 == 0 || i%5 == 0 || i%17 == 0 || i%257 == 0 {
			continue
		}
		g := gf16.T(2).Pow(uint32(i))
		generators = append(generators, g)
	}
}

// NewCoderPAR2Vandermonde constructs a Coder using the standard PAR2 Vandermonde matrix.
func NewCoderPAR2Vandermonde(dataShards, parityShards int) (*Coder, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return nil, errors.New("invalid shard counts")
	}
	if dataShards > len(generators) {
		return nil, errors.New("too many data shards for generator limit")
	}
	if parityShards > (1<<16)-1 {
		return nil, errors.New("too many parity shards for GF(2^16)")
	}

	parityMatrix, err := NewVandermondeMatrix(parityShards, dataShards, generators)
	if err != nil {
		return nil, err
	}
	return &Coder{
		dataShards:   dataShards,
		parityShards: parityShards,
		parityMatrix: parityMatrix,
	}, nil
}

func applyMatrixSlice(ctx context.Context, m Matrix, in, out [][]byte, outStart, outEnd, dataStart, dataEnd int) {
	for i := outStart; i < outEnd; i++ {
		if ctx.Err() != nil {
			return
		}
		outSlice := out[i][dataStart:dataEnd]
		c := m.At(i, 0)
		inSlice := in[0][dataStart:dataEnd]
		gf16.MulByteSliceLE(c, inSlice, outSlice)
		for j := 1; j < len(in); j++ {
			c := m.At(i, j)
			inSlice := in[j][dataStart:dataEnd]
			gf16.MulAndAddByteSliceLE(c, inSlice, outSlice)
		}
	}
}

func applyMatrixParallelData(ctx context.Context, m Matrix, in, out [][]byte, numGoroutines int) error {
	if len(in) == 0 || len(out) == 0 {
		return nil
	}
	if len(in[0]) != len(out[0]) {
		return errors.New("mismatched data slice lengths")
	}
	if numGoroutines < 1 {
		numGoroutines = DefaultNumGoroutines()
	}

	dataLength := len(out[0])
	// Split bytes within the shards for horizontal thread scaling.
	// Capped at multiples of 16 bytes for optimal SIMD memory alignments.
	perGoroutineDataLength := max((dataLength+numGoroutines-1)/numGoroutines, 16)
	rem := perGoroutineDataLength % 16
	if rem != 0 {
		perGoroutineDataLength += (16 - rem)
	}

	actualNumGoroutines := (dataLength + perGoroutineDataLength - 1) / perGoroutineDataLength
	if actualNumGoroutines < 2 {
		applyMatrixSlice(ctx, m, in, out, 0, m.Rows(), 0, dataLength)
		return ctx.Err()
	}

	var wg sync.WaitGroup
	wg.Add(actualNumGoroutines)
	for i := range actualNumGoroutines {
		go func(i int) {
			defer wg.Done()
			start := i * perGoroutineDataLength
			end := min(start+perGoroutineDataLength, dataLength)
			applyMatrixSlice(ctx, m, in, out, 0, m.Rows(), start, end)
		}(i)
	}
	wg.Wait()
	return ctx.Err()
}

func makeReconstructionMatrix(dataShards int, availableRows, missingRows, usedParityRows []int, parityMatrix Matrix) (Matrix, error) {
	m, err := NewMatrix(len(usedParityRows), len(usedParityRows))
	if err != nil {
		return Matrix{}, err
	}
	for i := range usedParityRows {
		for j := range usedParityRows {
			k := usedParityRows[i]
			l := missingRows[j]
			m.Set(i, j, parityMatrix.At(k, l))
		}
	}

	n, err := NewMatrix(len(usedParityRows), dataShards)
	if err != nil {
		return Matrix{}, err
	}
	for i := range usedParityRows {
		for j := range dataShards {
			if j < len(availableRows) {
				k := usedParityRows[i]
				l := availableRows[j]
				n.Set(i, j, parityMatrix.At(k, l))
			} else if i == j-len(availableRows) {
				n.Set(i, j, 1)
			} else {
				n.Set(i, j, 0)
			}
		}
	}

	return m.RowReduceForInverse(n)
}

func validateShardLengths(data, parity [][]byte) (int, error) {
	sliceLen := -1
	check := func(s []byte) error {
		if s == nil {
			return nil
		}
		if sliceLen == -1 {
			sliceLen = len(s)
		} else if len(s) != sliceLen {
			return errors.New("mismatched shard lengths")
		}
		return nil
	}

	for _, s := range data {
		if err := check(s); err != nil {
			return 0, err
		}
	}
	for _, s := range parity {
		if err := check(s); err != nil {
			return 0, err
		}
	}
	return sliceLen, nil
}

// ErrNotEnoughParity is returned when there are not enough parity shards to reconstruct.
var ErrNotEnoughParity = errors.New("not enough parity shards to perform reconstruction")

var (
	ErrInvalidDataShardCount   = errors.New("invalid data shard count")
	ErrInvalidParityShardCount = errors.New("invalid parity shard count")
)

// Reconstruct takes a list of data shards and parity shards, some of which
// can be nil (representing missing shards), and reconstructs the missing data
// shards in-place inside the data slice.
func (c *Coder) Reconstruct(ctx context.Context, data, parity [][]byte, numGoroutines int) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(data) != c.dataShards {
		return ErrInvalidDataShardCount
	}
	if len(parity) > c.parityShards {
		return ErrInvalidParityShardCount
	}

	sliceLen, err := validateShardLengths(data, parity)
	if err != nil {
		return err
	}

	var availableRows, missingRows []int
	var input [][]byte
	for i, dataShard := range data {
		if dataShard != nil {
			availableRows = append(availableRows, i)
			input = append(input, dataShard)
		} else {
			missingRows = append(missingRows, i)
		}
	}

	if len(missingRows) == 0 {
		return nil // all data shards present
	}

	// Gather required parity shards
	var usedParityRows []int
	for i := 0; i < len(parity) && len(input) < c.dataShards; i++ {
		if parity[i] != nil {
			usedParityRows = append(usedParityRows, i)
			input = append(input, parity[i])
		}
	}

	if len(input) < c.dataShards {
		return ErrNotEnoughParity
	}

	reconstructionMatrix, err := makeReconstructionMatrix(c.dataShards, availableRows, missingRows, usedParityRows, c.parityMatrix)
	if err != nil {
		return err
	}

	reconstructedData := make([][]byte, len(missingRows))
	for i := range reconstructedData {
		reconstructedData[i] = make([]byte, sliceLen)
	}

	err = applyMatrixParallelData(ctx, reconstructionMatrix, input, reconstructedData, numGoroutines)
	if err != nil {
		return err
	}

	for i, r := range missingRows {
		data[r] = reconstructedData[i]
	}

	return nil
}

// GenerateParity generates parity shards for the given data shards.
// Primarily used for testing and generating test datasets.
func (c *Coder) GenerateParity(ctx context.Context, data [][]byte, numGoroutines int) ([][]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(data) != c.dataShards {
		return nil, errors.New("invalid data shard count")
	}
	sliceLen, err := validateShardLengths(data, nil)
	if err != nil {
		return nil, err
	}
	if sliceLen == -1 {
		sliceLen = 0
	}

	parity := make([][]byte, c.parityShards)
	for i := range parity {
		parity[i] = make([]byte, sliceLen)
	}
	err = applyMatrixParallelData(ctx, c.parityMatrix, data, parity, numGoroutines)
	return parity, err
}
