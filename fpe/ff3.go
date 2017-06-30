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

	if bigTmp.Exp(bigRadix, big.NewInt(int64(maxMessageLength/2)), nil).Cmp(big2Pow96) >= 0 {
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
