package fpe

import (
	"math/big"
)

// ceil(x / 2^n)
func ceilRsh(x int, n uint) int {
	if x & ((1 << n) - 1) == 0 {
		return x >> n
	}

	return x >> n + 1
}

// ceil(log2(x))
func ceilLog2(x *big.Int) int {
	n := x.BitLen()
	if n == 0 || n == 1 {
		return 0
	}

	// Handle the case where x is a power of two
	y := big.NewInt(int64(1))
	y.Sub(x, y)
	y.AndNot(x, y)

	if x.Cmp(y) == 0 {
		return n - 1
	}

	return n
}
