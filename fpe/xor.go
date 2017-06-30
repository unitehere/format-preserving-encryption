package fpe

// xorBytes takes two byte slices, a and b, and returns a new byte slice. The
// contents of the new byte slice are the result of a xor b.
func xorBytes(a, b []byte) (result []byte) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	result = make([]byte, n)
	for i := 0; i < n; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}
