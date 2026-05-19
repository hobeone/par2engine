package rs

import (
	"reflect"
	"testing"

	"github.com/hobeone/par2engine/gf16"
)

func TestNewIdentityMatrix(t *testing.T) {
	m, err := NewIdentityMatrix(3)
	if err != nil {
		t.Fatalf("failed to create identity matrix: %v", err)
	}
	expected := []gf16.T{
		1, 0, 0,
		0, 1, 0,
		0, 0, 1,
	}
	if !reflect.DeepEqual(m.elements, expected) {
		t.Fatalf("identity matrix mismatch: got %v", m.elements)
	}
}

func TestNewVandermondeMatrix(t *testing.T) {
	generators := []gf16.T{2, 3}
	m, err := NewVandermondeMatrix(3, 2, generators)
	if err != nil {
		t.Fatalf("failed to create Vandermonde matrix: %v", err)
	}
	// a[i, j] = gen[j]^i
	// Row 0: 2^0 = 1, 3^0 = 1
	// Row 1: 2^1 = 2, 3^1 = 3
	// Row 2: 2^2 = 4, 3^2 = 5  (in GF, 3^2 = 3.Times(3) = 5)
	expected := []gf16.T{
		1, 1,
		2, 3,
		4, 5,
	}
	if !reflect.DeepEqual(m.elements, expected) {
		t.Fatalf("Vandermonde matrix mismatch: got %v", m.elements)
	}
}

func TestMatrixInverse(t *testing.T) {
	// Simple 2x2 non-singular matrix
	m, err := NewMatrixFromSlice(2, 2, []gf16.T{
		3, 5,
		7, 11,
	})
	if err != nil {
		t.Fatalf("failed to create matrix: %v", err)
	}

	mInv, err := m.Inverse()
	if err != nil {
		t.Fatalf("Inverse failed: %v", err)
	}

	// Verify M * MInv == I
	// Result row 0 col 0: 3*mInv[0,0] ^ 5*mInv[1,0]
	// Result row 0 col 1: 3*mInv[0,1] ^ 5*mInv[1,1]
	// Result row 1 col 0: 7*mInv[0,0] ^ 11*mInv[1,0]
	// Result row 1 col 1: 7*mInv[0,1] ^ 11*mInv[1,1]
	r00 := m.At(0, 0).Times(mInv.At(0, 0)) ^ m.At(0, 1).Times(mInv.At(1, 0))
	r01 := m.At(0, 0).Times(mInv.At(0, 1)) ^ m.At(0, 1).Times(mInv.At(1, 1))
	r10 := m.At(1, 0).Times(mInv.At(0, 0)) ^ m.At(1, 1).Times(mInv.At(1, 0))
	r11 := m.At(1, 0).Times(mInv.At(0, 1)) ^ m.At(1, 1).Times(mInv.At(1, 1))

	if r00 != 1 || r01 != 0 || r10 != 0 || r11 != 1 {
		t.Fatalf("M * MInv != I: got [%d %d; %d %d]", r00, r01, r10, r11)
	}
}

func TestMatrixInverseSingular(t *testing.T) {
	// Singular matrix (row 1 is multiple of row 0)
	m, err := NewMatrixFromSlice(2, 2, []gf16.T{
		3, 5,
		gf16.T(3).Times(gf16.T(2)), gf16.T(5).Times(gf16.T(2)),
	})
	if err != nil {
		t.Fatalf("failed to create matrix: %v", err)
	}

	_, err = m.Inverse()
	if err == nil {
		t.Fatal("expected error inverting singular matrix, got nil")
	}
}
