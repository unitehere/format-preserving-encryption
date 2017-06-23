package fpe

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
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

