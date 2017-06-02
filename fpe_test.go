package fpe

import (
	"crypto/aes"
	"encoding/hex"
	"log"
	"testing"
)

func TestFF1Encrypt(t *testing.T) {
	t.Log("Testing FF1 encryption (case 1)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3C", 10, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789", []byte{})
	checkError(err)
	checkExpectedResult(t, "2433477484", msg)
}

func TestFF1Decrypt(t *testing.T) {
	t.Log("Testing FF1 decryption (case 1)...")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3C", 10, 1, 20, 16)
	plaintext, err := ff1.Decrypt("2433477484", []byte{})
	checkError(err)
	checkExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt2(t *testing.T) {
	t.Log("Testing FF1 encryption (case 2)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3C", 10, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	checkError(err)
	checkExpectedResult(t, "6124200773", msg)
}

func TestFF1Decrypt2(t *testing.T) {
	t.Log("Testing FF1 decryption (case 2)...")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3C", 10, 1, 20, 16)
	plaintext, err := ff1.Decrypt("6124200773", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	checkError(err)
	checkExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt3(t *testing.T) {
	t.Log("Testing FF1 encryption (case 3)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3C", 36, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789abcdefghi", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	checkError(err)
	checkExpectedResult(t, "a9tv40mll9kdu509eum", msg)
}

func TestFF1Decrypt3(t *testing.T) {
	t.Log("Testing FF1 decryption (case 3)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3C", 36, 1, 20, 16)
	plaintext, err := ff1.Decrypt("a9tv40mll9kdu509eum", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	checkError(err)
	checkExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF1Encrypt4(t *testing.T) {
	t.Log("Testing FF1 encryption (case 4)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789", []byte{})
	checkError(err)
	checkExpectedResult(t, "2830668132", msg)
}

func TestFF1Decrypt4(t *testing.T) {
	t.Log("Testing FF1 decryption (case 4)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, 1, 20, 16)
	plaintext, err := ff1.Decrypt("2830668132", []byte{})
	checkError(err)
	checkExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt5(t *testing.T) {
	t.Log("Testing FF1 encryption (case 5)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	checkError(err)
	checkExpectedResult(t, "2496655549", msg)
}

func TestFF1Decrypt5(t *testing.T) {
	t.Log("Testing FF1 decryption (case 5)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, 1, 20, 16)
	plaintext, err := ff1.Decrypt("2496655549", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	checkError(err)
	checkExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt6(t *testing.T) {
	t.Log("Testing FF1 encryption (case 6)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 36, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789abcdefghi", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	checkError(err)
	checkExpectedResult(t, "xbj3kv35jrawxv32ysr", msg)
}

func TestFF1Decrypt6(t *testing.T) {
	t.Log("Testing FF1 decryption (case 6)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 36, 1, 20, 16)
	plaintext, err := ff1.Decrypt("xbj3kv35jrawxv32ysr", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	checkError(err)
	checkExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF1Encrypt7(t *testing.T) {
	t.Log("Testing FF1 encryption (case 7)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789", []byte{})
	checkError(err)
	checkExpectedResult(t, "6657667009", msg)
}

func TestFF1Decrypt7(t *testing.T) {
	t.Log("Testing FF1 decryption (case 7)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 1, 20, 16)
	plaintext, err := ff1.Decrypt("6657667009", []byte{})
	checkError(err)
	checkExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt8(t *testing.T) {
	t.Log("Testing FF1 encryption (case 8)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	checkError(err)
	checkExpectedResult(t, "1001623463", msg)
}

func TestFF1Decrypt8(t *testing.T) {
	t.Log("Testing FF1 decryption (case 8)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 1, 20, 16)
	plaintext, err := ff1.Decrypt("1001623463", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	checkError(err)
	checkExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt9(t *testing.T) {
	t.Log("Testing FF1 encryption (case 9)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 1, 20, 16)
	msg, err := ff1.Encrypt("0123456789abcdefghi", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	checkError(err)
	checkExpectedResult(t, "xs8a0azh2avyalyzuwd", msg)
}

func TestFF1Decrypt9(t *testing.T) {
	t.Log("Testing FF1 decryption (case 9)... ")
	ff1 := setupFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 1, 20, 16)
	plaintext, err := ff1.Decrypt("xs8a0azh2avyalyzuwd", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	checkError(err)
	checkExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func setupFF1(keyString string, radix, minMessageLength, maxMessageLength, maxTweakLength int) (ff1 FF1) {
	key, err := hex.DecodeString(keyString)
	checkError(err)
	cipher, err := aes.NewCipher(key)
	checkError(err)

	ff1 = NewFF1(cipher, radix, minMessageLength, maxMessageLength, maxTweakLength)
	return ff1
}

func checkExpectedResult(t *testing.T, expected, actual string) {
	if expected != actual {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expected, actual)
	}
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
