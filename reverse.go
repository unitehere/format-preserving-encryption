package fpe

// reverse takes a string as input and returns its reverse.
func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// reverse takes a byte slice as input and returns a new byte slice with the
// order of the bytes reversed.
func reverseBytes(b []byte) []byte {
	reverse := make([]byte, len(b))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		reverse[i], reverse[j] = b[j], b[i]
	}
	return reverse
}
