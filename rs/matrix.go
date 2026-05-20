package rs

import (
	"errors"
	"unsafe"

	"github.com/hobeone/par2engine/gf16"
)

// Matrix represents a 2D array of elements of GF(2^16).
// It stores elements in row-major order.
type Matrix struct {
	rows, cols int
	elements   []gf16.T
}

func checkDims(rows, cols int) error {
	if rows <= 0 || cols <= 0 {
		return errors.New("invalid matrix dimensions")
	}
	return nil
}

// NewMatrix creates an empty rows x cols matrix.
func NewMatrix(rows, cols int) (Matrix, error) {
	if err := checkDims(rows, cols); err != nil {
		return Matrix{}, err
	}
	return Matrix{rows, cols, make([]gf16.T, rows*cols)}, nil
}

// NewMatrixFromSlice creates a matrix using pre-allocated row-major elements.
func NewMatrixFromSlice(rows, cols int, elements []gf16.T) (Matrix, error) {
	if err := checkDims(rows, cols); err != nil {
		return Matrix{}, err
	}
	if len(elements) != rows*cols {
		return Matrix{}, errors.New("element count must match rows * cols")
	}
	elCopy := make([]gf16.T, len(elements))
	copy(elCopy, elements)
	return Matrix{rows, cols, elCopy}, nil
}

// NewIdentityMatrix creates an n x n identity matrix.
func NewIdentityMatrix(n int) (Matrix, error) {
	if err := checkDims(n, n); err != nil {
		return Matrix{}, err
	}
	elements := make([]gf16.T, n*n)
	for i := range n {
		elements[i*n+i] = 1
	}
	return Matrix{n, n, elements}, nil
}

// NewVandermondeMatrix creates an r x c Vandermonde matrix where
// a[i, j] = generator[j] ^ i.
func NewVandermondeMatrix(rows, cols int, generators []gf16.T) (Matrix, error) {
	if err := checkDims(rows, cols); err != nil {
		return Matrix{}, err
	}
	if len(generators) < cols {
		return Matrix{}, errors.New("too few generators for Vandermonde matrix")
	}
	elements := make([]gf16.T, rows*cols)
	for i := range rows {
		for j := range cols {
			elements[i*cols+j] = generators[j].Pow(uint32(i))
		}
	}
	return Matrix{rows, cols, elements}, nil
}

// NewCauchyMatrix creates a Cauchy matrix where a[i, j] = 1 / (x[i] + y[j]).
func NewCauchyMatrix(rows, cols int, x, y []gf16.T) (Matrix, error) {
	if err := checkDims(rows, cols); err != nil {
		return Matrix{}, err
	}
	if len(x) < rows || len(y) < cols {
		return Matrix{}, errors.New("insufficient x or y elements for Cauchy matrix")
	}
	elements := make([]gf16.T, rows*cols)
	for i := range rows {
		for j := range cols {
			sum := x[i] ^ y[j]
			if sum == 0 {
				return Matrix{}, errors.New("cauchy matrix division by zero")
			}
			elements[i*cols+j] = sum.Inverse()
		}
	}
	return Matrix{rows, cols, elements}, nil
}

func (m Matrix) checkRow(i int) {
	if i < 0 || i >= m.rows {
		panic("row index out of bounds")
	}
}

func (m Matrix) checkCol(j int) {
	if j < 0 || j >= m.cols {
		panic("column index out of bounds")
	}
}

// At returns the element at a[i, j].
func (m Matrix) At(i, j int) gf16.T {
	m.checkRow(i)
	m.checkCol(j)
	return m.elements[i*m.cols+j]
}

// Set sets the element at a[i, j]. Mutates the matrix (safe for internal RS math).
func (m Matrix) Set(i, j int, val gf16.T) {
	m.checkRow(i)
	m.checkCol(j)
	m.elements[i*m.cols+j] = val
}

// Rows returns the number of rows.
func (m Matrix) Rows() int { return m.rows }

// Cols returns the number of columns.
func (m Matrix) Cols() int { return m.cols }

// Clone returns a deep copy of the matrix.
func (m Matrix) Clone() (Matrix, error) {
	return NewMatrixFromSlice(m.rows, m.cols, m.elements)
}

// row returns the slice for row i.
func (m Matrix) row(i int) []gf16.T {
	m.checkRow(i)
	return m.elements[i*m.cols : (i+1)*m.cols]
}

func (m Matrix) swapRows(i, j int) {
	if i == j {
		return
	}
	rI := m.row(i)
	rJ := m.row(j)
	for k := 0; k < m.cols; k++ {
		rI[k], rJ[k] = rJ[k], rI[k]
	}
}

// castTToByteSlice safely casts a []gf16.T to []byte using modern unsafe.Slice (Go 1.17+).
// Zero-allocation and compiler-optimized.
// NOTE: assumes little-endian host (x86/ARM64). PAR2 uses LE byte order.
func castTToByteSlice(ts []gf16.T) []byte {
	if len(ts) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&ts[0])), len(ts)*2)
}

func (m Matrix) scaleRow(i int, c gf16.T) {
	row := m.row(i)
	rowBytes := castTToByteSlice(row)
	gf16.MulByteSliceLE(c, rowBytes, rowBytes)
}

func (m Matrix) addScaledRow(dest, src int, c gf16.T) {
	rowSrc := m.row(src)
	rowDest := m.row(dest)
	gf16.MulAndAddByteSliceLE(c, castTToByteSlice(rowSrc), castTToByteSlice(rowDest))
}

// rowReduceForInverse performs Gaussian elimination on m (mutating it)
// and performs the identical operations on n (mutating it).
func (m Matrix) rowReduceForInverse(n Matrix) error {
	// Convert to row echelon form
	for i := 0; i < m.rows; i++ {
		var pivot gf16.T
		for j := i; j < m.rows; j++ {
			if m.At(j, i) != 0 {
				m.swapRows(i, j)
				n.swapRows(i, j)
				pivot = m.At(i, i)
				break
			}
		}
		if pivot == 0 {
			return errors.New("singular matrix")
		}

		pivotInv := pivot.Inverse()
		m.scaleRow(i, pivotInv)
		n.scaleRow(i, pivotInv)

		// Zero out elements below pivot
		for j := i + 1; j < m.rows; j++ {
			t := m.At(j, i)
			if t != 0 {
				m.addScaledRow(j, i, t)
				n.addScaledRow(j, i, t)
			}
		}
	}

	// Convert to reduced row echelon form (zero out elements above pivot)
	for i := 0; i < m.rows; i++ {
		for j := 0; j < i; j++ {
			t := m.At(j, i)
			if t != 0 {
				m.addScaledRow(j, i, t)
				n.addScaledRow(j, i, t)
			}
		}
	}

	return nil
}

// Inverse returns the inverse of a square matrix.
func (m Matrix) Inverse() (Matrix, error) {
	if m.rows != m.cols {
		return Matrix{}, errors.New("cannot invert non-square matrix")
	}
	n, err := NewIdentityMatrix(m.cols)
	if err != nil {
		return Matrix{}, err
	}
	mClone, err := m.Clone()
	if err != nil {
		return Matrix{}, err
	}
	err = mClone.rowReduceForInverse(n)
	if err != nil {
		return Matrix{}, err
	}
	return n, nil
}

// RowReduceForInverse solves the system m * X = n using row reduction.
// Returns the row-reduced copy of n (which is X).
func (m Matrix) RowReduceForInverse(n Matrix) (Matrix, error) {
	if m.rows != m.cols {
		return Matrix{}, errors.New("cannot row-reduce non-square matrix")
	}
	if n.rows != m.rows {
		return Matrix{}, errors.New("n must have the same number of rows as m")
	}
	nReduced, err := n.Clone()
	if err != nil {
		return Matrix{}, err
	}
	mClone, err := m.Clone()
	if err != nil {
		return Matrix{}, err
	}
	err = mClone.rowReduceForInverse(nReduced)
	if err != nil {
		return Matrix{}, err
	}
	return nReduced, nil
}
