package fpe

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
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

func NewFF1(cipher cipher.Block, radix int, minMessageLength int, maxMessageLength int, maxTweakLength int) (ff1 FF1) {
	return FF1{
		cipher:           cipher,
		radix:            radix,
		minMessageLength: minMessageLength,
		maxMessageLength: maxMessageLength,
		maxTweakLength:   maxTweakLength}
}

func (ff1 *FF1) setup(message string) {
	ff1.messageLength = len(message)
	ff1.firstHalfLength = int(math.Floor(float64(ff1.messageLength) / 2.0))
	ff1.secondHalfLength = ff1.messageLength - ff1.firstHalfLength
	ff1.firstHalf, ff1.secondHalf = message[0:ff1.firstHalfLength], message[ff1.firstHalfLength:ff1.messageLength]
	ff1.messageByteLength = int(math.Ceil(math.Ceil(float64(ff1.secondHalfLength)*math.Log2(float64(ff1.radix))) / 8.0))
	ff1.adjustedByteStringLength = int(4*math.Ceil(float64(ff1.messageByteLength)/4.0) + 4)

	fixedBlockPart1 := uint64(0x0102010000000a00) | (uint64(ff1.radix) << 16) | uint64(ff1.firstHalfLength%256)
	fixedBlockPart2 := (uint64(ff1.messageLength) << 32) | uint64(ff1.maxTweakLength)
	binary.BigEndian.PutUint64(ff1.fixedBlock[:8], fixedBlockPart1)
	binary.BigEndian.PutUint64(ff1.fixedBlock[8:], fixedBlockPart2)
}

func (ff1 *FF1) PseudoRandomFunction(blockString []byte) (block []byte) {
	numBlocks := len(blockString) / 16
	block = make([]byte, 16)
	for index := 0; index < numBlocks; index++ {
		ff1.cipher.Encrypt(block, xorBytes(block, blockString[index*16:index*16+16]))
	}

	return block
}

func (ff1 *FF1) Encrypt(plaintext string, tweak []byte) (message string, err error) {
	ff1.setup(plaintext)

	fmt.Println("Message Length (n): ", ff1.messageLength)
	fmt.Println("First Half Length (u): ", ff1.firstHalfLength)
	fmt.Println("Second Half Length (v): ", ff1.secondHalfLength)
	fmt.Println("First Half (A): ", ff1.firstHalf)
	fmt.Println("Second Half (B): ", ff1.secondHalf)
	fmt.Println("Byte Length (b): ", ff1.messageByteLength)
	fmt.Println("Adjusted Byte Length (d): ", ff1.adjustedByteStringLength)
	fmt.Println("Fixed Block (P): ", ff1.fixedBlock)
	fmt.Println()

	variableBlockLength := len(tweak) + 1 + ff1.messageByteLength
	variableBlockLength = variableBlockLength + (16 - variableBlockLength%16) //round variable block length to next multiple of 16 bytes (128 bits)
	variableBlock := make([]byte, variableBlockLength)
	copy(variableBlock, tweak)
	for round := 0; round < 10; round++ {
		fmt.Println("Round #", round, ":")

		variableBlock[variableBlockLength-ff1.messageByteLength-1] = byte(round)
		secondHalfNumber, err := strconv.ParseUint(ff1.secondHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}
		tmpBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(tmpBuf, secondHalfNumber)
		copy(variableBlock[variableBlockLength-ff1.messageByteLength:], tmpBuf[8-ff1.messageByteLength:])
		blockString := make([]byte, 32)
		copy(blockString, ff1.fixedBlock[:])
		copy(blockString[16:], variableBlock)
		block := ff1.PseudoRandomFunction(append(ff1.fixedBlock[:], variableBlock...))

		byteString := make([]byte, int(math.Ceil(float64(ff1.adjustedByteStringLength)/16.0))*16)
		copy(byteString[0:16], block)
		mask := make([]byte, 2)
		for blockIndex := 1; blockIndex*16 < len(block); blockIndex++ {
			binary.BigEndian.PutUint16(mask, uint16(blockIndex))
			ff1.cipher.Encrypt(byteString[blockIndex*16:(blockIndex+1)*16], xorBytes(block, mask))
		}
		adjustedByteString := byteString[0:ff1.adjustedByteStringLength]
		adjustedByteStringNumber := big.NewInt(0)
		adjustedByteStringNumber.SetBytes(adjustedByteString)

		modifier := ff1.secondHalfLength
		if round%2 == 0 {
			modifier = ff1.firstHalfLength
		}

		firstHalfNumber, err := strconv.ParseInt(ff1.firstHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}

		resultingNumber := big.NewInt(firstHalfNumber)
		resultingNumber.Add(big.NewInt(firstHalfNumber), adjustedByteStringNumber)
		resultingNumber.Mod(resultingNumber, big.NewInt(int64(math.Pow(float64(ff1.radix), float64(modifier)))))

		resultingString := strconv.FormatUint(resultingNumber.Uint64(), ff1.radix)
		if len(resultingString) < modifier {
			padding := strings.Repeat("0", modifier-len(resultingString))
			resultingString = padding + resultingString
		}
		ff1.firstHalf = ff1.secondHalf
		ff1.secondHalf = resultingString

		fmt.Println("Variable Block (Q): ", variableBlock)
		fmt.Println("Block (R): ", block)
		fmt.Printf("Byte String (S): %x\n", adjustedByteString)
		fmt.Println("Byte String as Number (y): ", adjustedByteStringNumber)
		fmt.Println("Modifier (m): ", modifier)
		fmt.Println("Resulting Number (c): ", resultingNumber)
		fmt.Println("Resulting String (C): ", resultingString)
		fmt.Println("New First Half(A): ", ff1.firstHalf)
		fmt.Println("New Second Half(B): ", ff1.secondHalf)

		fmt.Println()
	}

	message = ff1.firstHalf + ff1.secondHalf

	fmt.Println("Encrypted Message (A || B): ", message)
	fmt.Println()

	return message, nil
}

func (ff1 *FF1) Decrypt(message string, tweak []byte) (plaintext string, err error) {
	ff1.setup(message)

	fmt.Println("Message Length (n): ", ff1.messageLength)
	fmt.Println("First Half Length (u): ", ff1.firstHalfLength)
	fmt.Println("Second Half Length (v): ", ff1.secondHalfLength)
	fmt.Println("First Half (A): ", ff1.firstHalf)
	fmt.Println("Second Half (B): ", ff1.secondHalf)
	fmt.Println("Byte Length (b): ", ff1.messageByteLength)
	fmt.Println("Adjusted Byte Length (d): ", ff1.adjustedByteStringLength)
	fmt.Println("Fixed Block (P): ", ff1.fixedBlock)
	fmt.Println()

	variableBlockLength := len(tweak) + 1 + ff1.messageByteLength
	variableBlockLength = variableBlockLength + (16 - variableBlockLength%16) //round variable block size to next multiple of 16
	variableBlock := make([]byte, variableBlockLength)
	copy(variableBlock, tweak)
	for round := 9; round >= 0; round-- {
		fmt.Println("Round #", round, ":")

		variableBlock[variableBlockLength-ff1.messageByteLength-1] = byte(round)
		firstHalfNumber, err := strconv.ParseUint(ff1.firstHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}
		tmpBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(tmpBuf, firstHalfNumber)
		copy(variableBlock[variableBlockLength-ff1.messageByteLength:], tmpBuf[8-ff1.messageByteLength:])
		blockString := make([]byte, 32)
		copy(blockString, ff1.fixedBlock[:])
		copy(blockString[16:], variableBlock)
		block := ff1.PseudoRandomFunction(append(ff1.fixedBlock[:], variableBlock...))

		byteString := make([]byte, int(math.Ceil(float64(ff1.adjustedByteStringLength)/16.0))*16)
		copy(byteString[0:16], block)
		mask := make([]byte, 2)
		for blockIndex := 1; blockIndex*16 < len(block); blockIndex++ {
			binary.BigEndian.PutUint16(mask, uint16(blockIndex))
			ff1.cipher.Encrypt(byteString[blockIndex*16:(blockIndex+1)*16], xorBytes(block, mask))
		}
		adjustedByteString := byteString[0:ff1.adjustedByteStringLength]
		adjustedByteStringNumber := big.NewInt(0)
		adjustedByteStringNumber.SetBytes(adjustedByteString)

		modifier := ff1.secondHalfLength
		if round%2 == 0 {
			modifier = ff1.firstHalfLength
		}

		secondHalfNumber, err := strconv.ParseInt(ff1.secondHalf, ff1.radix, 64)
		if err != nil {
			return message, err
		}

		resultingNumber := big.NewInt(secondHalfNumber)
		resultingNumber.Sub(big.NewInt(secondHalfNumber), adjustedByteStringNumber)
		resultingNumber.Mod(resultingNumber, big.NewInt(int64(math.Pow(float64(ff1.radix), float64(modifier)))))

		resultingString := strconv.FormatUint(resultingNumber.Uint64(), ff1.radix)
		if len(resultingString) < modifier {
			padding := strings.Repeat("0", modifier-len(resultingString))
			resultingString = padding + resultingString
		}
		ff1.secondHalf = ff1.firstHalf
		ff1.firstHalf = resultingString

		fmt.Println("Variable Block (Q): ", variableBlock)
		fmt.Println("Block (R): ", block)
		fmt.Printf("Byte String (S): %x\n", adjustedByteString)
		fmt.Println("Byte String as Number (y): ", adjustedByteStringNumber)
		fmt.Println("Modifier (m): ", modifier)
		fmt.Println("Resulting Number (c): ", resultingNumber)
		fmt.Println("Resulting String (C): ", resultingString)
		fmt.Println("New First Half(A): ", ff1.firstHalf)
		fmt.Println("New Second Half(B): ", ff1.secondHalf)

		fmt.Println()
	}

	plaintext = ff1.firstHalf + ff1.secondHalf

	fmt.Println("Decrypted Message (A || B): ", plaintext)
	fmt.Println()

	return plaintext, nil
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
