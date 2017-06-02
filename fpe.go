package fpe

import (
	"crypto/cipher"
	"encoding/binary"
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

func NewFF1(cipher cipher.Block, radix, minMessageLength, maxMessageLength, maxTweakLength int) (ff1 FF1) {
	return FF1{
		cipher:           cipher,
		radix:            radix,
		minMessageLength: minMessageLength,
		maxMessageLength: maxMessageLength,
		maxTweakLength:   maxTweakLength}
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
		firstHalfNumber, err := strconv.ParseInt(ff1.firstHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}
		resultNumber := big.NewInt(0).Add(big.NewInt(firstHalfNumber), adjustedByteStringNumber)
		resultNumber.Mod(resultNumber, big.NewInt(int64(math.Pow(float64(ff1.radix), float64(resultStringLength)))))

		resultString := zeroLeftPad(strconv.FormatUint(resultNumber.Uint64(), ff1.radix), resultStringLength)
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
		secondHalfNumber, err := strconv.ParseInt(ff1.secondHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}
		resultNumber := big.NewInt(0).Sub(big.NewInt(secondHalfNumber), adjustedByteStringNumber)
		resultNumber.Mod(resultNumber, big.NewInt(int64(math.Pow(float64(ff1.radix), float64(resultStringLength)))))

		resultString := zeroLeftPad(strconv.FormatUint(resultNumber.Uint64(), ff1.radix), resultStringLength)
		ff1.secondHalf = ff1.firstHalf
		ff1.firstHalf = resultString
	}

	plaintext = ff1.firstHalf + ff1.secondHalf
	return plaintext, nil
}

func zeroLeftPad(input string, totalLength int) (output string) {
	length := len(input)
	output = input
	if length < totalLength {
		output = strings.Repeat("0", totalLength-length) + output
	}
	return output
}

// Utility Functions

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
