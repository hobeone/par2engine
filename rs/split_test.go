package rs

import (
	"fmt"
	"testing"
)

// perGoroutineSplit decides how much of a chunk each goroutine multiplies, and
// the alignment it picks is what decides whether gf16's vector kernels consume a
// whole slice or leave a tail for the scalar path. These tests pin the
// alignment, not the arithmetic that produces it.

func TestPerGoroutineSplitIsVectorAligned(t *testing.T) {
	for _, dataLength := range []int{1, 16, 64, 100, 368, 7648, 11600, 15968, 38128, 1 << 20} {
		for _, goroutines := range []int{1, 2, 8, 32, 64} {
			t.Run(fmt.Sprintf("len=%d/g=%d", dataLength, goroutines), func(t *testing.T) {
				split := perGoroutineSplit(dataLength, goroutines)

				if split%vectorBlockBytes != 0 {
					t.Errorf("perGoroutineSplit(%d, %d) = %d, want a multiple of %d -- "+
						"a split that is not lets every goroutine leave a scalar tail",
						dataLength, goroutines, split, vectorBlockBytes)
				}
				if split <= 0 {
					t.Fatalf("perGoroutineSplit(%d, %d) = %d, want a positive size", dataLength, goroutines, split)
				}

				// Every byte must land in exactly one goroutine's range.
				n := (dataLength + split - 1) / split
				if covered := n * split; covered < dataLength {
					t.Errorf("%d goroutines of %d bytes cover %d, short of %d", n, split, covered, dataLength)
				}
				if n > 1 && (n-1)*split >= dataLength {
					t.Errorf("%d goroutines of %d bytes leaves the last one empty for %d bytes", n, split, dataLength)
				}
			})
		}
	}
}

// TestPerGoroutineSplitUsesEveryGoroutine guards the other direction: rounding
// up costs parallelism, because a larger split means fewer ranges. A chunk big
// enough to give every goroutine a whole block must still do so.
func TestPerGoroutineSplitUsesEveryGoroutine(t *testing.T) {
	const goroutines = 32
	dataLength := goroutines * vectorBlockBytes * 4

	split := perGoroutineSplit(dataLength, goroutines)
	if got := (dataLength + split - 1) / split; got != goroutines {
		t.Errorf("perGoroutineSplit(%d, %d) = %d yields %d ranges, want %d",
			dataLength, goroutines, split, got, goroutines)
	}
}
