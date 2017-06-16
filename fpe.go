/*
Package fpe implements format preserving encryption, as defined in NIST
Special Publication 800-38G.

This package implements both FF1 and FF3 modes of format preserving
encryption and decryption.
*/
package fpe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"
)

// The FF1 type allows for encryption and decryption of messages using the FF1
// mode of format preserving encryption. See the NewFF1, (ff1 *FF1) Encrypt,
// and (ff1 *FF1) Decrypt functions for more detail.
type FF1 struct {
	cipher           cipher.Block
	radix            int
	minMessageLength int
	maxMessageLength int
	maxTweakLength   int

	messageLength       int
	firstHalfLength     int
	secondHalfLength    int
	firstHalf           string
	secondHalf          string
	messageByteLength   int
	cipheredBlockLength int
	fixedBlock          [16]byte
}

// The FF3 type allows for encryption and decryption of messages using the FF3
// mode of format preserving encryption. See the NewFF3, (ff3 *FF3) Encrypt,
// and (ff3 *FF3) Decrypt functions for more detail.
type FF3 struct {
	cipher           cipher.Block
	radix            int
	minMessageLength int
	maxMessageLength int

	messageLength    int
	firstHalfLength  int
	secondHalfLength int
	firstHalf        string
	secondHalf       string
	tweakLeft        [4]byte
	tweakRight       [4]byte
}

// NewFF1 returns a new FF1 struct for encrypting and decrypting messages using
// the FF1 mode of format preserving encryption. It will also return any errors
// encountered in creating an AES key.
// The keyString argument should be the AES key string in hexadecimal, either
// 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The radix argument should be the number of characters in the alphabet that
// will be used. It can be any integer from 2 to 36 inclusive.
// The minMessageLength and maxMessageLength arguments should be the minimum
// and maximum message lengths that will be allowed.
// The maxTweakLength argument should be the maximum length of tweaks, in bytes.
func NewFF1(keyString string, radix, minMessageLength, maxMessageLength, maxTweakLength int) (ff1 FF1, err error) {
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return FF1{}, err
	}
	cph, err := aes.NewCipher(key)
	if err != nil {
		return FF1{}, err
	}

	if radix < 2 || radix > 65536 {
		return FF1{}, errors.New("radix must be in [2..2^16]")
	}

	if minMessageLength < 2 || minMessageLength > maxMessageLength || maxMessageLength >= 1 << 32 {
		return FF1{}, errors.New("2 <= minlen <= maxlen < 2^32")
	}

	bigRadix := big.NewInt(int64(radix))
	bigMinLen := big.NewInt(int64(minMessageLength))
	if bigRadix.Exp(bigRadix, bigMinLen, nil).Cmp(big.NewInt(int64(100))) < 0 {
		return FF1{}, errors.New("radix^minlen >= 100")
	}

	return FF1{
		cipher:           cph,
		radix:            radix,
		minMessageLength: minMessageLength,
		maxMessageLength: maxMessageLength,
		maxTweakLength:   maxTweakLength}, nil
}

// NewFF3 returns a new FF3 struct for encrypting and decrypting messages using
// the FF3 mode of format preserving encryption. It will also return any errors
// encountered in creating an AES key.
// The keyString argument should be the AES key string in hexadecimal, either
// 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The radix argument should be the number of characters in the alphabet that
// will be used. It can be any integer from 2 to 36 inclusive.
// The minMessageLength and maxMessageLength arguments should be the minimum
// and maximum message lengths that will be allowed.
func NewFF3(keyString string, radix, minMessageLength, maxMessageLength int) (ff3 FF3, err error) {
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return FF3{}, err
	}
	cph, err := aes.NewCipher(reverseBytes(key))
	if err != nil {
		return FF3{}, err
	}

	if radix < 2 || radix > 65536 {
		return FF3{}, errors.New("radix must be in [2..2^16]")
	}

	if minMessageLength < 2 || minMessageLength > maxMessageLength {
		return FF3{}, errors.New("2 <= minlen <= maxlen < 2 * floor(log_radix(2^96))")
	}

	bigTmp := big.NewInt(int64(0))
	bigRadix := big.NewInt(int64(radix))

	big2Pow96 := big.NewInt(int64(1))
	big2Pow96.Lsh(big2Pow96, 96)

	if bigTmp.Exp(bigRadix, big.NewInt(int64(maxMessageLength / 2)), nil).Cmp(big2Pow96) >= 0 {
		return FF3{}, errors.New("2 <= minlen <= maxlen < 2 * floor(log_radix(2^96))")
	}

	bigMinLen := big.NewInt(int64(minMessageLength))
	if bigTmp.Exp(bigRadix, bigMinLen, nil).Cmp(big.NewInt(int64(100))) < 0 {
		return FF3{}, errors.New("radix^minlen >= 100")
	}

	return FF3{
		cipher:           cph,
		radix:            radix,
		minMessageLength: minMessageLength,
		maxMessageLength: maxMessageLength}, nil
}

// Encrypt uses the AES key string and arguments used to construct ff1 to
// encrypt a message. It returns the encrypted message, along with any error
// encountered during encryption.
// The plaintext argument should be the message to encrypt.
// The tweak argument should be the tweak to use in the encryption process.
func (ff1 *FF1) Encrypt(plaintext string, tweak []byte) (message string, err error) {
	err = ff1.prepareConstants(plaintext, tweak)
	if err != nil {
		return message, err
	}

	radixBig := big.NewInt(int64(ff1.radix))

	radixPowFirstHalfLen := big.NewInt(int64(ff1.firstHalfLength))
	radixPowFirstHalfLen.Exp(radixBig, radixPowFirstHalfLen, nil)

	radixPowSecondHalfLen := big.NewInt(int64(ff1.secondHalfLength))
	radixPowSecondHalfLen.Exp(radixBig, radixPowSecondHalfLen, nil)

	variableBlockLength := len(tweak) + 1 + ff1.messageByteLength
	variableBlockLength = variableBlockLength + (16 - variableBlockLength%16) //round variable block length to next multiple of 16 bytes (128 bits)
	variableBlock := make([]byte, variableBlockLength)
	copy(variableBlock, tweak)
	for round := 0; round < 10; round++ {
		err := ff1.adjustVariableBlock(&variableBlock, round, ff1.secondHalf)
		if err != nil {
			return message, err
		}
		block := ff1.pseudoRandomFunction(append(ff1.fixedBlock[:], variableBlock...))
		cipheredBlockNumber := ff1.calculateCipheredBlockNumber(block)

		resultStringLength, mod := ff1.secondHalfLength, radixPowSecondHalfLen
		if round%2 == 0 {
			resultStringLength, mod = ff1.firstHalfLength, radixPowFirstHalfLen
		}
		firstHalfNumber, err := strconv.ParseUint(ff1.firstHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}
		resultNumber := big.NewInt(int64(firstHalfNumber))
		resultNumber.Add(resultNumber, cipheredBlockNumber)
		resultNumber.Mod(resultNumber, mod)

		resultString := resultNumber.Text(ff1.radix)
		resultString = zeroLeftPad(resultString, resultStringLength)
		ff1.firstHalf = ff1.secondHalf
		ff1.secondHalf = resultString
	}

	message = ff1.firstHalf + ff1.secondHalf
	return message, nil
}

// Decrypt uses the AES key string and arguments used to construct ff1 to
// decrypt a message. It returns the decrypted message, along with any error
// encountered during decryption.
// The plaintext argument should be the message to decrypt.
// The tweak argument should be the tweak to use in the decryption process.
func (ff1 *FF1) Decrypt(message string, tweak []byte) (plaintext string, err error) {
	err = ff1.prepareConstants(message, tweak)
	if err != nil {
		return message, err
	}

	radixBig := big.NewInt(int64(ff1.radix))

	radixPowFirstHalfLen := big.NewInt(int64(ff1.firstHalfLength))
	radixPowFirstHalfLen.Exp(radixBig, radixPowFirstHalfLen, nil)

	radixPowSecondHalfLen := big.NewInt(int64(ff1.secondHalfLength))
	radixPowSecondHalfLen.Exp(radixBig, radixPowSecondHalfLen, nil)

	variableBlockLength := len(tweak) + 1 + ff1.messageByteLength
	variableBlockLength = variableBlockLength + (16 - variableBlockLength%16) //round variable block size to next multiple of 16
	variableBlock := make([]byte, variableBlockLength)
	copy(variableBlock, tweak)
	for round := 9; round >= 0; round-- {
		err := ff1.adjustVariableBlock(&variableBlock, round, ff1.firstHalf)
		if err != nil {
			return message, err
		}
		block := ff1.pseudoRandomFunction(append(ff1.fixedBlock[:], variableBlock...))
		cipheredBlockNumber := ff1.calculateCipheredBlockNumber(block)

		resultStringLength, mod := ff1.secondHalfLength, radixPowSecondHalfLen
		if round%2 == 0 {
			resultStringLength, mod = ff1.firstHalfLength, radixPowFirstHalfLen
		}
		secondHalfNumber, err := strconv.ParseUint(ff1.secondHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}
		resultNumber := big.NewInt(int64(secondHalfNumber))
		resultNumber.Sub(resultNumber, cipheredBlockNumber)
		resultNumber.Mod(resultNumber, mod)

		resultString := resultNumber.Text(ff1.radix)
		resultString = zeroLeftPad(resultString, resultStringLength)
		ff1.secondHalf = ff1.firstHalf
		ff1.firstHalf = resultString
	}

	plaintext = ff1.firstHalf + ff1.secondHalf
	return plaintext, nil
}

// Encrypt uses the AES key string and arguments used to construct ff3 to
// encrypt a message. It returns the encrypted message, along with any error
// encountered during encryption.
// The plaintext argument should be the message to encrypt.
// The tweak argument should be the tweak to use in the encryption process.
func (ff3 *FF3) Encrypt(plaintext string, tweak [8]byte) (message string, err error) {
	err = ff3.prepareConstants(plaintext, tweak)
	if err != nil {
		return message, err
	}

	radixBig := big.NewInt(int64(ff3.radix))

	radixPowFirstHalfLen := big.NewInt(int64(ff3.firstHalfLength))
	radixPowFirstHalfLen.Exp(radixBig, radixPowFirstHalfLen, nil)

	radixPowSecondHalfLen := big.NewInt(int64(ff3.secondHalfLength))
	radixPowSecondHalfLen.Exp(radixBig, radixPowSecondHalfLen, nil)

	for round := 0; round < 8; round++ {
		resultStringLength, tweakHalf, mod := ff3.secondHalfLength, ff3.tweakLeft, radixPowSecondHalfLen
		if round%2 == 0 {
			resultStringLength, tweakHalf, mod = ff3.firstHalfLength, ff3.tweakRight, radixPowFirstHalfLen
		}

		cipheredBlockNumber, err := ff3.calculateCipheredBlockNumber(round, ff3.secondHalf, tweakHalf)
		if err != nil {
			return message, err
		}

		firstHalfNumber, err := strconv.ParseUint(reverse(ff3.firstHalf), ff3.radix, 64)
		if err != nil {
			return message, err
		}
		resultNumber := big.NewInt(int64(firstHalfNumber))
		resultNumber.Add(resultNumber, cipheredBlockNumber)
		resultNumber.Mod(resultNumber, mod)
		resultString := resultNumber.Text(ff3.radix)
		resultString = reverse(zeroLeftPad(resultString, resultStringLength))

		ff3.firstHalf = ff3.secondHalf
		ff3.secondHalf = resultString
	}

	message = ff3.firstHalf + ff3.secondHalf
	return message, nil
}

// Decrypt uses the AES key string and arguments used to construct ff3 to
// decrypt a message. It returns the decrypted message, along with any error
// encountered during decryption.
// The plaintext argument should be the message to decrypt.
// The tweak argument should be the tweak to use in the decryption process.
func (ff3 *FF3) Decrypt(message string, tweak [8]byte) (plaintext string, err error) {
	err = ff3.prepareConstants(message, tweak)
	if err != nil {
		return plaintext, err
	}

	radixBig := big.NewInt(int64(ff3.radix))

	radixPowFirstHalfLen := big.NewInt(int64(ff3.firstHalfLength))
	radixPowFirstHalfLen.Exp(radixBig, radixPowFirstHalfLen, nil)

	radixPowSecondHalfLen := big.NewInt(int64(ff3.secondHalfLength))
	radixPowSecondHalfLen.Exp(radixBig, radixPowSecondHalfLen, nil)

	for round := 7; round >= 0; round-- {
		resultStringLength, tweakHalf, mod := ff3.secondHalfLength, ff3.tweakLeft, radixPowSecondHalfLen
		if round%2 == 0 {
			resultStringLength, tweakHalf, mod = ff3.firstHalfLength, ff3.tweakRight, radixPowFirstHalfLen
		}

		cipheredBlockNumber, err := ff3.calculateCipheredBlockNumber(round, ff3.firstHalf, tweakHalf)
		if err != nil {
			return plaintext, err
		}

		firstHalfNumber, err := strconv.ParseUint(reverse(ff3.secondHalf), ff3.radix, 64)
		if err != nil {
			return plaintext, err
		}
		resultNumber := big.NewInt(int64(firstHalfNumber))
		resultNumber.Sub(resultNumber, cipheredBlockNumber)
		resultNumber.Mod(resultNumber, mod)
		resultString := resultNumber.Text(ff3.radix)
		resultString = reverse(zeroLeftPad(resultString, resultStringLength))

		ff3.secondHalf = ff3.firstHalf
		ff3.firstHalf = resultString
	}

	plaintext = ff3.firstHalf + ff3.secondHalf
	return plaintext, nil
}

// Utility Functions for FF1

// prepareConstants prepares the ff1 struct based on the given message and tweak for
// encryption or decryption. It sets some constants that will be used in the
// encryption or decryption calculation and returns any error that is
// encountered during the process.
func (ff1 *FF1) prepareConstants(message string, tweak []byte) error {
	if len(message) <= 0 {
		return errors.New("message length was not non-zero")
	}
	if len(message) < ff1.minMessageLength {
		return errors.New("message length was less than the minimum allowable length")
	}
	if len(message) > ff1.maxMessageLength {
		return errors.New("message length was greater than the maximum allowable length")
	}
	if len(tweak) > ff1.maxTweakLength {
		return errors.New("tweak length was greater than the maximum allowable length")
	}

	ff1.messageLength = len(message)
	ff1.firstHalfLength = ff1.messageLength / 2
	ff1.secondHalfLength = ff1.messageLength - ff1.firstHalfLength
	ff1.firstHalf, ff1.secondHalf = message[0:ff1.firstHalfLength], message[ff1.firstHalfLength:ff1.messageLength]

	tmp := big.NewInt(int64(ff1.radix))
	tmp.Exp(tmp, big.NewInt(int64(ff1.secondHalfLength)), nil)
	ff1.messageByteLength = ceilRsh(ceilLog2(tmp), 3)
	ff1.cipheredBlockLength = 4 * ceilRsh(ff1.messageByteLength, 2) + 4

	fixedBlockPart1 := uint64(0x0102010000000a00) | (uint64(ff1.radix) << 16) | uint64(ff1.firstHalfLength%256)
	fixedBlockPart2 := (uint64(ff1.messageLength) << 32) | uint64(len(tweak))
	binary.BigEndian.PutUint64(ff1.fixedBlock[:8], fixedBlockPart1)
	binary.BigEndian.PutUint64(ff1.fixedBlock[8:], fixedBlockPart2)

	return nil
}

// adjustVariableBlock adjusts a variable block that changes slightly for every
// round of the FF1 algorithm. It modifies the variableBlock argument in place
// and returns any error encountered when parsing the message string.
// The round argument should be the number of the current round in the FF1
// algorithm.
// The messageHalf is half of the input to the encryption or decryption round.
// This can be the first half (A) or the second half (B) depending on whether
// the function is being called during Encrypt or Decrypt.
func (ff1 *FF1) adjustVariableBlock(variableBlock *[]byte, round int, messageHalf string) error {
	variableBlockLength := len(*variableBlock)
	(*variableBlock)[variableBlockLength-ff1.messageByteLength-1] = byte(round)
	messageHalfNumber, err := strconv.ParseUint(messageHalf, ff1.radix, 64)
	if err != nil {
		return err
	}
	tmpBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tmpBuf, messageHalfNumber)
	copy((*variableBlock)[variableBlockLength-ff1.messageByteLength:], tmpBuf[8-ff1.messageByteLength:])
	return nil
}

// pseudoRandomFunction returns a block that has been run through an AES cipher
// function as part of the FF1 encryption or decryption algorithm. It takes a
// combination of the fixed and variable blocks concatenated together and
// returns the resulting byte slice.
func (ff1 *FF1) pseudoRandomFunction(blockString []byte) (block []byte) {
	numBlocks := len(blockString) / 16
	block = make([]byte, 16)
	for index := 0; index < numBlocks; index++ {
		ff1.cipher.Encrypt(block, xorBytes(block, blockString[index*16:index*16+16]))
	}

	return block
}

// calculateCipheredBlockNumber takes a byte slice as input and runs it through
// an AES cipher function. It then converts the resulting byte slice into an
// integer and returns it as a result.
func (ff1 *FF1) calculateCipheredBlockNumber(block []byte) (cipheredBlockNumber *big.Int) {
	byteString := make([]byte, 16 * ceilRsh(ff1.cipheredBlockLength, 4))
	copy(byteString[0:16], block)
	mask := make([]byte, 2)
	for blockIndex := 1; blockIndex*16 < len(block); blockIndex++ {
		binary.BigEndian.PutUint16(mask, uint16(blockIndex))
		ff1.cipher.Encrypt(byteString[blockIndex*16:(blockIndex+1)*16], xorBytes(block, mask))
	}
	cipheredBlock := byteString[0:ff1.cipheredBlockLength]
	cipheredBlockNumber = big.NewInt(0)
	cipheredBlockNumber.SetBytes(cipheredBlock)
	return cipheredBlockNumber
}

// Utility Functions for FF3

// prepareConstants prepares the ff3 struct based on the given message and tweak for
// encryption or decryption. It sets some constants that will be used in the
// encryption or decryption calculation and returns any error that is
// encountered during the process.
func (ff3 *FF3) prepareConstants(message string, tweak [8]byte) error {
	if len(message) <= 0 {
		return errors.New("message length was not non-zero")
	}
	if len(message) < ff3.minMessageLength {
		return errors.New("message length was less than the minimum allowable length")
	}
	if len(message) > ff3.maxMessageLength {
		return errors.New("message length was greater than the maximum allowable length")
	}

	ff3.messageLength = len(message)
	ff3.firstHalfLength = ceilRsh(ff3.messageLength, 1)
	ff3.secondHalfLength = ff3.messageLength - ff3.firstHalfLength
	ff3.firstHalf, ff3.secondHalf = message[0:ff3.firstHalfLength], message[ff3.firstHalfLength:ff3.messageLength]
	copy(ff3.tweakLeft[:], tweak[0:4])
	copy(ff3.tweakRight[:], tweak[4:8])

	return nil
}

// calculateCipheredBlockNumber assembles a block based on the round number of
// the FF3 encryption or decryption algorithm, half of the message being
// encrypted or decrypted, and half of the tweak. It then runs the block through
// an AES cipher function, converts the resulting byte slice into an
// integer, and returns the integer as a result along with any error that is
// encountered in parsing the message string.
func (ff3 *FF3) calculateCipheredBlockNumber(round int, messageHalf string, tweakHalf [4]byte) (cipheredBlockNumber *big.Int, err error) {
	block := [16]byte{}
	cipheredBlock := [16]byte{}
	roundMask := make([]byte, 4)
	binary.BigEndian.PutUint32(roundMask, uint32(round))
	copy(block[0:4], xorBytes(tweakHalf[:], roundMask))

	reverseSecondHalf := reverse(messageHalf)
	reverseSecondHalfNumber := big.NewInt(0)
	if _, ok := reverseSecondHalfNumber.SetString(reverseSecondHalf, ff3.radix); ok {
		tmp := reverseSecondHalfNumber.Bytes()
		if len(tmp) > 12 {
			return cipheredBlockNumber, errors.New("message was too long: half the message cannot fit in 12 bytes")
		}
		copy(block[16-len(tmp):16], tmp)
	} else {
		return cipheredBlockNumber, errors.New("couldn't interpret numerical string")
	}

	ff3.cipher.Encrypt(cipheredBlock[:], reverseBytes(block[:]))
	copy(cipheredBlock[:], reverseBytes(cipheredBlock[:]))
	cipheredBlockNumber = big.NewInt(0).SetBytes(cipheredBlock[:])

	return cipheredBlockNumber, nil
}

// String and Byte Operations

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

// ceil(x / 2^n)
func ceilRsh(x int, n uint) int {
	if x & ((1 << n) - 1) == 0 {
		return x >> n
	} else {
		return x >> n + 1
	}
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
	} else {
		return n
	}
}