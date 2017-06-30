package fpe

import "strings"

// zeroLeftPad left pads a copy of an input string with '0' characters until the
// new string reaches at least the desired total length and returns the result.
// The input argument is the string to left pad.
// The totalLength argument should be the desired length of the new string.
func zeroLeftPad(input string, totalLength int) (output string) {
	length := len(input)
	output = input
	if length < totalLength {
		output = strings.Repeat("0", totalLength-length) + output
	}
	return output
}
