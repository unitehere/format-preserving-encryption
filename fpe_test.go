package fpe

import (
	"crypto/aes"
	"encoding/hex"
	"log"
	"testing"
)

func TestFF1Encrypt(t *testing.T) {
	t.Log("Testing FF1 encryption (case 1)... ")
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	CheckError(err)
	cipher, err := aes.NewCipher(key)
	CheckError(err)

	ff1 := NewFF1(cipher, 10, 10, 10, 0)
	msg, err := ff1.Encrypt("0123456789", []byte{})
	CheckError(err)

	expectedResult := "2433477484"
	if msg != expectedResult {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expectedResult, msg)
	}
}

func TestFF1Decrypt(t *testing.T) {
	t.Log("Testing FF1 decryption (case 1)...")
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	CheckError(err)
	cipher, err := aes.NewCipher(key)
	CheckError(err)

	ff1 := NewFF1(cipher, 10, 10, 10, 0)
	plaintext, err := ff1.Decrypt("2433477484", []byte{0})
	CheckError(err)

	expectedResult := "0123456789"
	if plaintext != expectedResult {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expectedResult, plaintext)
	}
}

func TestFF1Encrypt2(t *testing.T) {
	t.Log("Testing FF1 encryption (case 2)... ")
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	CheckError(err)
	cipher, err := aes.NewCipher(key)
	CheckError(err)

	ff1 := NewFF1(cipher, 10, 10, 10, 10)
	msg, err := ff1.Encrypt("0123456789", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	CheckError(err)

	expectedResult := "6124200773"
	if msg != expectedResult {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expectedResult, msg)
	}
}

func TestFF1Decrypt2(t *testing.T) {
	t.Log("Testing FF1 decryption (case 2)...")
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	CheckError(err)
	cipher, err := aes.NewCipher(key)
	CheckError(err)

	ff1 := NewFF1(cipher, 10, 10, 10, 10)
	plaintext, err := ff1.Decrypt("6124200773", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	CheckError(err)

	expectedResult := "0123456789"
	if plaintext != expectedResult {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expectedResult, plaintext)
	}
}

func TestFF1Encrypt3(t *testing.T) {
	t.Log("Testing FF1 encryption (case 3)... ")
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	CheckError(err)
	cipher, err := aes.NewCipher(key)
	CheckError(err)

	ff1 := NewFF1(cipher, 36, 1, 20, 11)
	msg, err := ff1.Encrypt("0123456789abcdefghi", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	CheckError(err)

	expectedResult := "a9tv40mll9kdu509eum"
	if msg != expectedResult {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expectedResult, msg)
	}
}

func TestFF1Decrypt3(t *testing.T) {
	t.Log("Testing FF1 decryption (case 3)... ")
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	CheckError(err)
	cipher, err := aes.NewCipher(key)
	CheckError(err)

	ff1 := NewFF1(cipher, 36, 1, 20, 11)
	msg, err := ff1.Decrypt("a9tv40mll9kdu509eum", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	CheckError(err)

	expectedResult := "0123456789abcdefghi"
	if msg != expectedResult {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expectedResult, msg)
	}
}

func TestFF1Encrypt4(t *testing.T) {
	t.Log("Testing FF1 encryption (case 4)... ")
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F")
	CheckError(err)
	cipher, err := aes.NewCipher(key)
	CheckError(err)

	ff1 := NewFF1(cipher, 10, 1, 20, 0)
	msg, err := ff1.Encrypt("0123456789", []byte{})
	CheckError(err)

	expectedResult := "2830668132"
	if msg != expectedResult {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expectedResult, msg)
	}
}

func TestFF1Decrypt4(t *testing.T) {
	t.Log("Testing FF1 decryption (case 4)... ")
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F")
	CheckError(err)
	cipher, err := aes.NewCipher(key)
	CheckError(err)

	ff1 := NewFF1(cipher, 10, 1, 20, 0)
	msg, err := ff1.Decrypt("2830668132", []byte{})
	CheckError(err)

	expectedResult := "0123456789"
	if msg != expectedResult {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expectedResult, msg)
	}
}

func CheckError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
