package fpe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
)

type FF1 struct {
	cipher           cipher.Block
	radix            int
	minMessageLength int
	maxMessageLength int
	maxTweakLength   int

	messageLength            int
	firstHalfLength          int
	secondHalfLength         int
	firstHalf                string
	secondHalf               string
	messageByteLength        int
	adjustedByteStringLength int
	fixedBlock               [16]byte
}

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

func NewFF1(keyString string, radix, minMessageLength, maxMessageLength, maxTweakLength int) (ff1 FF1, err error) {
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return FF1{}, err
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return FF1{}, err
	}

	return FF1{
		cipher:           cipher,
		radix:            radix,
		minMessageLength: minMessageLength,
		maxMessageLength: maxMessageLength,
		maxTweakLength:   maxTweakLength}, nil
}

func NewFF3(keyString string, radix, minMessageLength, maxMessageLength int) (ff3 FF3, err error) {
	key, err := hex.DecodeString(keyString)
	if err != nil {
		return FF3{}, err
	}
	cipher, err := aes.NewCipher(reverseBytes(key))
	if err != nil {
		return FF3{}, err
	}

	return FF3{
		cipher:           cipher,
		radix:            radix,
		minMessageLength: minMessageLength,
		maxMessageLength: maxMessageLength}, nil
}

func (ff1 *FF1) setup(message string, tweak []byte) error {
	if len(message) <= 0 {
		return errors.New("Message length was not non-zero.")
	}
	if len(message) < ff1.minMessageLength {
		return errors.New("Message length was less than the minimum allowable length.")
	}
	if len(message) > ff1.maxMessageLength {
		return errors.New("Message length was greater than the maximum allowable length.")
	}
	if len(tweak) > ff1.maxTweakLength {
		return errors.New("Tweak length was greater than the maximum allowable length.")
	}

	ff1.messageLength = len(message)
	ff1.firstHalfLength = int(math.Floor(float64(ff1.messageLength) / 2.0))
	ff1.secondHalfLength = ff1.messageLength - ff1.firstHalfLength
	ff1.firstHalf, ff1.secondHalf = message[0:ff1.firstHalfLength], message[ff1.firstHalfLength:ff1.messageLength]
	ff1.messageByteLength = int(math.Ceil(math.Ceil(float64(ff1.secondHalfLength)*math.Log2(float64(ff1.radix))) / 8.0))
	ff1.adjustedByteStringLength = int(4*math.Ceil(float64(ff1.messageByteLength)/4.0) + 4)

	fixedBlockPart1 := uint64(0x0102010000000a00) | (uint64(ff1.radix) << 16) | uint64(ff1.firstHalfLength%256)
	fixedBlockPart2 := (uint64(ff1.messageLength) << 32) | uint64(len(tweak))
	binary.BigEndian.PutUint64(ff1.fixedBlock[:8], fixedBlockPart1)
	binary.BigEndian.PutUint64(ff1.fixedBlock[8:], fixedBlockPart2)

	return nil
}

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

func (ff1 *FF1) pseudoRandomFunction(blockString []byte) (block []byte) {
	numBlocks := len(blockString) / 16
	block = make([]byte, 16)
	for index := 0; index < numBlocks; index++ {
		ff1.cipher.Encrypt(block, xorBytes(block, blockString[index*16:index*16+16]))
	}

	return block
}

func (ff1 *FF1) calculateAdjustedByteStringNumber(block []byte) (adjustedByteStringNumber *big.Int) {
	byteString := make([]byte, int(math.Ceil(float64(ff1.adjustedByteStringLength)/16.0))*16)
	copy(byteString[0:16], block)
	mask := make([]byte, 2)
	for blockIndex := 1; blockIndex*16 < len(block); blockIndex++ {
		binary.BigEndian.PutUint16(mask, uint16(blockIndex))
		ff1.cipher.Encrypt(byteString[blockIndex*16:(blockIndex+1)*16], xorBytes(block, mask))
	}
	adjustedByteString := byteString[0:ff1.adjustedByteStringLength]
	adjustedByteStringNumber = big.NewInt(0)
	adjustedByteStringNumber.SetBytes(adjustedByteString)
	return adjustedByteStringNumber
}

func (ff1 *FF1) Encrypt(plaintext string, tweak []byte) (message string, err error) {
	err = ff1.setup(plaintext, tweak)
	if err != nil {
		return message, err
	}

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
		adjustedByteStringNumber := ff1.calculateAdjustedByteStringNumber(block)

		resultStringLength := ff1.secondHalfLength
		if round%2 == 0 {
			resultStringLength = ff1.firstHalfLength
		}
		firstHalfNumber, err := strconv.ParseUint(ff1.firstHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}
		resultNumber := big.NewInt(0).Add(big.NewInt(int64(firstHalfNumber)), adjustedByteStringNumber)
		resultNumber.Mod(resultNumber, big.NewInt(int64(math.Pow(float64(ff1.radix), float64(resultStringLength)))))

		resultString := resultNumber.Text(ff1.radix)
		resultString = zeroLeftPad(resultString, resultStringLength)
		ff1.firstHalf = ff1.secondHalf
		ff1.secondHalf = resultString
	}

	message = ff1.firstHalf + ff1.secondHalf
	return message, nil
}

func (ff1 *FF1) Decrypt(message string, tweak []byte) (plaintext string, err error) {
	err = ff1.setup(message, tweak)
	if err != nil {
		return message, err
	}

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
		adjustedByteStringNumber := ff1.calculateAdjustedByteStringNumber(block)

		resultStringLength := ff1.secondHalfLength
		if round%2 == 0 {
			resultStringLength = ff1.firstHalfLength
		}
		secondHalfNumber, err := strconv.ParseUint(ff1.secondHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}
		resultNumber := big.NewInt(0).Sub(big.NewInt(int64(secondHalfNumber)), adjustedByteStringNumber)
		resultNumber.Mod(resultNumber, big.NewInt(int64(math.Pow(float64(ff1.radix), float64(resultStringLength)))))

		resultString := resultNumber.Text(ff1.radix)
		resultString = zeroLeftPad(resultString, resultStringLength)
		ff1.secondHalf = ff1.firstHalf
		ff1.firstHalf = resultString
	}

	plaintext = ff1.firstHalf + ff1.secondHalf
	return plaintext, nil
}

func (ff3 *FF3) setup(message string, tweak [8]byte) error {
	if len(message) <= 0 {
		return errors.New("Message length was not non-zero.")
	}
	if len(message) < ff3.minMessageLength {
		return errors.New("Message length was less than the minimum allowable length.")
	}
	if len(message) > ff3.maxMessageLength {
		return errors.New("Message length was greater than the maximum allowable length.")
	}

	ff3.messageLength = len(message)
	ff3.firstHalfLength = int(math.Ceil(float64(ff3.messageLength) / 2.0))
	ff3.secondHalfLength = ff3.messageLength - ff3.firstHalfLength
	ff3.firstHalf, ff3.secondHalf = message[0:ff3.firstHalfLength], message[ff3.firstHalfLength:ff3.messageLength]
	copy(ff3.tweakLeft[:], tweak[0:4])
	copy(ff3.tweakRight[:], tweak[4:8])

	return nil
}

func (ff3 *FF3) calculateCipheredBlock(round int, messageHalf string, tweakHalf [4]byte) (cipheredBlock [16]byte, err error) {
	block := [16]byte{}
	cipheredBlock = [16]byte{}
	roundMask := make([]byte, 4)
	binary.BigEndian.PutUint32(roundMask, uint32(round))
	copy(block[0:4], xorBytes(tweakHalf[:], roundMask))

	reverseSecondHalf := reverse(messageHalf)
	reverseSecondHalfNumber := big.NewInt(0)
	if _, ok := reverseSecondHalfNumber.SetString(reverseSecondHalf, ff3.radix); ok {
		tmp := reverseSecondHalfNumber.Bytes()
		if len(tmp) > 12 {
			return cipheredBlock, errors.New("Message was too long: half the message cannot fit in 12 bytes.")
		}
		copy(block[16-len(tmp):16], tmp)
	} else {
		return cipheredBlock, errors.New("Couldn't interpret numerical string.")
	}

	ff3.cipher.Encrypt(cipheredBlock[:], reverseBytes(block[:]))
	copy(cipheredBlock[:], reverseBytes(cipheredBlock[:]))

	return cipheredBlock, nil
}

func (ff3 *FF3) Encrypt(plaintext string, tweak [8]byte) (message string, err error) {
	err = ff3.setup(plaintext, tweak)
	if err != nil {
		return message, err
	}

	for round := 0; round < 8; round++ {
		resultStringLength, tweakHalf := ff3.secondHalfLength, ff3.tweakLeft
		if round%2 == 0 {
			resultStringLength, tweakHalf = ff3.firstHalfLength, ff3.tweakRight
		}

		cipheredBlock, err := ff3.calculateCipheredBlock(round, ff3.secondHalf, tweakHalf)
		if err != nil {
			return message, err
		}

		cipheredBlockNumber := big.NewInt(0).SetBytes(cipheredBlock[:])
		firstHalfNumber, err := strconv.ParseUint(reverse(ff3.firstHalf), ff3.radix, 64)
		if err != nil {
			return message, err
		}
		resultNumber := big.NewInt(0).Add(big.NewInt(int64(firstHalfNumber)), cipheredBlockNumber)
		resultNumber.Mod(resultNumber, big.NewInt(int64(math.Pow(float64(ff3.radix), float64(resultStringLength)))))
		resultString := resultNumber.Text(ff3.radix)
		resultString = reverse(zeroLeftPad(resultString, resultStringLength))

		ff3.firstHalf = ff3.secondHalf
		ff3.secondHalf = resultString
	}

	message = ff3.firstHalf + ff3.secondHalf
	return message, nil
}

func (ff3 *FF3) Decrypt(message string, tweak [8]byte) (plaintext string, err error) {
	err = ff3.setup(message, tweak)
	if err != nil {
		return plaintext, err
	}

	for round := 7; round >= 0; round-- {
		resultStringLength, tweakHalf := ff3.secondHalfLength, ff3.tweakLeft
		if round%2 == 0 {
			resultStringLength, tweakHalf = ff3.firstHalfLength, ff3.tweakRight
		}

		cipheredBlock, err := ff3.calculateCipheredBlock(round, ff3.firstHalf, tweakHalf)
		if err != nil {
			return plaintext, err
		}

		cipheredBlockNumber := big.NewInt(0).SetBytes(cipheredBlock[:])
		firstHalfNumber, err := strconv.ParseUint(reverse(ff3.secondHalf), ff3.radix, 64)
		if err != nil {
			return plaintext, err
		}
		resultNumber := big.NewInt(0).Sub(big.NewInt(int64(firstHalfNumber)), cipheredBlockNumber)
		resultNumber.Mod(resultNumber, big.NewInt(int64(math.Pow(float64(ff3.radix), float64(resultStringLength)))))
		resultString := resultNumber.Text(ff3.radix)
		resultString = reverse(zeroLeftPad(resultString, resultStringLength))

		ff3.secondHalf = ff3.firstHalf
		ff3.firstHalf = resultString
	}

	plaintext = ff3.firstHalf + ff3.secondHalf
	return plaintext, nil
}

// Utility Functions

func zeroLeftPad(input string, totalLength int) (output string) {
	length := len(input)
	output = input
	if length < totalLength {
		output = strings.Repeat("0", totalLength-length) + output
	}
	return output
}

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

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func reverseBytes(b []byte) []byte {
	reverse := make([]byte, len(b))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		reverse[i], reverse[j] = b[j], b[i]
	}
	return reverse
}
