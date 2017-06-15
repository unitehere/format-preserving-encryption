package fpe

import (
	"log"
	"testing"
)

func TestNewFF1WithInvalidHexString(t *testing.T) {
	t.Log("Testing NewFF1 with invalid hex string... ")
	_, err := NewFF1("2B7E151628AED2A6XYZ7158809CF4F3C", 10, 2, 20, 16)
	assertError(t, err)
}

func TestNewFF1WithInvalidKey(t *testing.T) {
	t.Log("Testing NewFF1 with invalid AES key... ")
	_, err := NewFF1("A1B2C3", 10, 2, 20, 16)
	assertError(t, err)
}

func TestNewFF3WithInvalidHexString(t *testing.T) {
	t.Log("Testing NewFF3 with invalid hex string... ")
	_, err := NewFF3("2B7E151628AED2A6XYZ7158809CF4F3C", 10, 2, 20)
	assertError(t, err)
}

func TestNewFF3WithInvalidKey(t *testing.T) {
	t.Log("Testing NewFF3 with invalid AES key... ")
	_, err := NewFF3("A1B2C3", 10, 1, 20)
	assertError(t, err)
}

func TestFF1Encrypt1(t *testing.T) {
	t.Log("Testing FF1 encryption (case 1)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789", []byte{})
	assertNoError(t, err)
	assertExpectedResult(t, "2433477484", msg)
}

func TestFF1Decrypt1(t *testing.T) {
	t.Log("Testing FF1 decryption (case 1)...")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20, 16)
	assertNoError(t, err)
	plaintext, err := ff1.Decrypt("2433477484", []byte{})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt2(t *testing.T) {
	t.Log("Testing FF1 encryption (case 2)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	assertNoError(t, err)
	assertExpectedResult(t, "6124200773", msg)
}

func TestFF1Decrypt2(t *testing.T) {
	t.Log("Testing FF1 decryption (case 2)...")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20, 16)
	assertNoError(t, err)
	plaintext, err := ff1.Decrypt("6124200773", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt3(t *testing.T) {
	t.Log("Testing FF1 encryption (case 3)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3C", 36, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789abcdefghi", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertNoError(t, err)
	assertExpectedResult(t, "a9tv40mll9kdu509eum", msg)
}

func TestFF1Decrypt3(t *testing.T) {
	t.Log("Testing FF1 decryption (case 3)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3C", 36, 2, 20, 16)
	assertNoError(t, err)
	plaintext, err := ff1.Decrypt("a9tv40mll9kdu509eum", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF1Encrypt4(t *testing.T) {
	t.Log("Testing FF1 encryption (case 4)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789", []byte{})
	assertNoError(t, err)
	assertExpectedResult(t, "2830668132", msg)
}

func TestFF1Decrypt4(t *testing.T) {
	t.Log("Testing FF1 decryption (case 4)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, 2, 20, 16)
	assertNoError(t, err)
	plaintext, err := ff1.Decrypt("2830668132", []byte{})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt5(t *testing.T) {
	t.Log("Testing FF1 encryption (case 5)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	assertNoError(t, err)
	assertExpectedResult(t, "2496655549", msg)
}

func TestFF1Decrypt5(t *testing.T) {
	t.Log("Testing FF1 decryption (case 5)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 10, 2, 20, 16)
	assertNoError(t, err)
	plaintext, err := ff1.Decrypt("2496655549", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt6(t *testing.T) {
	t.Log("Testing FF1 encryption (case 6)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 36, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789abcdefghi", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertNoError(t, err)
	assertExpectedResult(t, "xbj3kv35jrawxv32ysr", msg)
}

func TestFF1Decrypt6(t *testing.T) {
	t.Log("Testing FF1 decryption (case 6)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", 36, 2, 20, 16)
	assertNoError(t, err)
	plaintext, err := ff1.Decrypt("xbj3kv35jrawxv32ysr", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF1Encrypt7(t *testing.T) {
	t.Log("Testing FF1 encryption (case 7)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789", []byte{})
	assertNoError(t, err)
	assertExpectedResult(t, "6657667009", msg)
}

func TestFF1Decrypt7(t *testing.T) {
	t.Log("Testing FF1 decryption (case 7)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20, 16)
	plaintext, err := ff1.Decrypt("6657667009", []byte{})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt8(t *testing.T) {
	t.Log("Testing FF1 encryption (case 8)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	assertNoError(t, err)
	assertExpectedResult(t, "1001623463", msg)
}

func TestFF1Decrypt8(t *testing.T) {
	t.Log("Testing FF1 decryption (case 8)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20, 16)
	assertNoError(t, err)
	plaintext, err := ff1.Decrypt("1001623463", []byte{0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789", plaintext)
}

func TestFF1Encrypt9(t *testing.T) {
	t.Log("Testing FF1 encryption (case 9)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 2, 20, 16)
	assertNoError(t, err)
	msg, err := ff1.Encrypt("0123456789abcdefghi", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertNoError(t, err)
	assertExpectedResult(t, "xs8a0azh2avyalyzuwd", msg)
}

func TestFF1Decrypt9(t *testing.T) {
	t.Log("Testing FF1 decryption (case 9)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 2, 20, 16)
	assertNoError(t, err)
	plaintext, err := ff1.Decrypt("xs8a0azh2avyalyzuwd", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF1EncryptNoMessage(t *testing.T) {
	t.Log("Testing FF1 encryption with no message... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 2, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Encrypt("", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1DecryptNoMessage(t *testing.T) {
	t.Log("Testing FF1 decryption with no message... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 2, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Decrypt("", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1EncryptShortMessage(t *testing.T) {
	t.Log("Testing FF1 encryption with message that is too short... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Encrypt("1234", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1DecryptShortMessage(t *testing.T) {
	t.Log("Testing FF1 decryption with message that is too short... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Decrypt("1234", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1EncryptLongMessage(t *testing.T) {
	t.Log("Testing FF1 encryption with message that is too long... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Encrypt("123456789012345678901", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1DecryptLongMessage(t *testing.T) {
	t.Log("Testing FF1 decryption with message that is too long... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Decrypt("123456789012345678901", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1EncryptInvalidMessage1(t *testing.T) {
	t.Log("Testing FF1 encryption with invalid message (case 1)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Encrypt("ABCDEFGHIJK12345", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1DecryptInvalidMessage1(t *testing.T) {
	t.Log("Testing FF1 decryption with invalid message (case 1)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Decrypt("12345AB", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1EncryptInvalidMessage2(t *testing.T) {
	t.Log("Testing FF1 encryption with invalid message (case 2)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Encrypt("JK12345", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1DecryptInvalidMessage2(t *testing.T) {
	t.Log("Testing FF1 decryption with invalid message (case 2)... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20, 16)
	assertNoError(t, err)
	_, err = ff1.Decrypt("JK12345", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1EncryptLongTweak(t *testing.T) {
	t.Log("Testing FF1 encryption with message that is too long... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20, 10)
	assertNoError(t, err)
	_, err = ff1.Encrypt("12345678901234567890", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF1DecryptLongTweak(t *testing.T) {
	t.Log("Testing FF1 decryption with message that is too long... ")
	ff1, err := NewFF1("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20, 10)
	assertNoError(t, err)
	_, err = ff1.Decrypt("12345678901234567890", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37})
	assertError(t, err)
}

func TestFF3Encrypt1(t *testing.T) {
	t.Log("Testing FF3 encryption (case 1)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "750918814058654607", msg)
}

func TestFF3Decrypt1(t *testing.T) {
	t.Log("Testing FF3 decryption (case 1)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("750918814058654607", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt2(t *testing.T) {
	t.Log("Testing FF3 encryption (case 2)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "018989839189395384", msg)
}

func TestFF3Decrypt2(t *testing.T) {
	t.Log("Testing FF3 decryption (case 2)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("018989839189395384", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt3(t *testing.T) {
	t.Log("Testing FF3 encryption (case 3)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "48598367162252569629397416226", msg)
}

func TestFF3Decrypt3(t *testing.T) {
	t.Log("Testing FF3 decryption (case 3)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("48598367162252569629397416226", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt4(t *testing.T) {
	t.Log("Testing FF3 encryption (case 4)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "34695224821734535122613701434", msg)
}

func TestFF3Decrypt4(t *testing.T) {
	t.Log("Testing FF3 decryption (case 4)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("34695224821734535122613701434", [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt5(t *testing.T) {
	t.Log("Testing FF3 encryption (case 5)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 26, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("0123456789abcdefghi", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "g2pk40i992fn20cjakb", msg)
}

func TestFF3Decrypt5(t *testing.T) {
	t.Log("Testing FF3 decryption (case 5)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 26, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("g2pk40i992fn20cjakb", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF3Encrypt6(t *testing.T) {
	t.Log("Testing FF3 encryption (case 6)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "646965393875028755", msg)
}

func TestFF3Decrypt6(t *testing.T) {
	t.Log("Testing FF3 decryption (case 6)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("646965393875028755", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt7(t *testing.T) {
	t.Log("Testing FF3 encryption (case 7)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "961610514491424446", msg)
}

func TestFF3Decrypt7(t *testing.T) {
	t.Log("Testing FF3 decryption (case 7)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("961610514491424446", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt8(t *testing.T) {
	t.Log("Testing FF3 encryption (case 8)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "53048884065350204541786380807", msg)
}

func TestFF3Decrypt8(t *testing.T) {
	t.Log("Testing FF3 decryption (case 8)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("53048884065350204541786380807", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt9(t *testing.T) {
	t.Log("Testing FF3 encryption (case 9)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "98083802678820389295041483512", msg)
}

func TestFF3Decrypt9(t *testing.T) {
	t.Log("Testing FF3 decryption (case 9)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("98083802678820389295041483512", [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt10(t *testing.T) {
	t.Log("Testing FF3 encryption (case 10)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 26, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("0123456789abcdefghi", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "i0ihe2jfj7a9opf9p88", msg)
}

func TestFF3Decrypt10(t *testing.T) {
	t.Log("Testing FF3 decryption (case 10)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 26, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("i0ihe2jfj7a9opf9p88", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF3Encrypt11(t *testing.T) {
	t.Log("Testing FF3 encryption (case 11)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "922011205562777495", msg)
}

func TestFF3Decrypt11(t *testing.T) {
	t.Log("Testing FF3 decryption (case 11)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("922011205562777495", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt12(t *testing.T) {
	t.Log("Testing FF3 encryption (case 12)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "504149865578056140", msg)
}

func TestFF3Decrypt12(t *testing.T) {
	t.Log("Testing FF3 decryption (case 12)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("504149865578056140", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt13(t *testing.T) {
	t.Log("Testing FF3 encryption (case 13)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "04344343235792599165734622699", msg)
}

func TestFF3Decrypt13(t *testing.T) {
	t.Log("Testing FF3 decryption (case 13)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("04344343235792599165734622699", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt14(t *testing.T) {
	t.Log("Testing FF3 encryption (case 14)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "30859239999374053872365555822", msg)
}

func TestFF3Decrypt14(t *testing.T) {
	t.Log("Testing FF3 decryption (case 14)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("30859239999374053872365555822", [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt15(t *testing.T) {
	t.Log("Testing FF3 encryption (case 15)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 26, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("0123456789abcdefghi", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "p0b2godfja9bhb7bk38", msg)
}

func TestFF3Decrypt15(t *testing.T) {
	t.Log("Testing FF3 decryption (case 15)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 26, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("p0b2godfja9bhb7bk38", [8]byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF3EncryptNoMessage(t *testing.T) {
	t.Log("Testing FF3 encryption with no message... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 2, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3DecryptNoMessage(t *testing.T) {
	t.Log("Testing FF3 decryption with no message... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 2, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3EncryptShortMessage(t *testing.T) {
	t.Log("Testing FF3 encryption with message that is too short... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("1234", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3DecryptShortMessage(t *testing.T) {
	t.Log("Testing FF3 decryption with message that is too short... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("1234", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3EncryptLongMessage(t *testing.T) {
	t.Log("Testing FF3 encryption with message that is too long... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("123456789012345678901", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3DecryptLongMessage(t *testing.T) {
	t.Log("Testing FF3 decryption with message that is too long... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("123456789012345678901", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3EncryptMessageTooLongForBlock(t *testing.T) {
	t.Log("Testing FF3 encryption with message that is too long for the block calculation... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 36)
	assertNoError(t, err)
	_, err = ff3.Encrypt("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3DecryptMessageTooLongForBlock(t *testing.T) {
	t.Log("Testing FF3 decryption with message that is too long for the block calculation... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 36)
	assertNoError(t, err)
	_, err = ff3.Decrypt("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", [8]byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3EncryptInvalidMessage1(t *testing.T) {
	t.Log("Testing FF3 encryption with invalid message (case 1)... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("12345ABCDE", [8]byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73})
	assertError(t, err)
}

func TestFF3DecryptInvalidMessage1(t *testing.T) {
	t.Log("Testing FF3 decryption with invalid message (case 1)... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("12345ABCDE", [8]byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73})
	assertError(t, err)
}

func TestFF3EncryptInvalidMessage2(t *testing.T) {
	t.Log("Testing FF3 encryption with invalid message (case 2)... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("JK12345", [8]byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73})
	assertError(t, err)
}

func TestFF3DecryptInvalidMessage2(t *testing.T) {
	t.Log("Testing FF3 decryption with invalid message (case 2)... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("JK12345", [8]byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73})
	assertError(t, err)
}

// Utility Functions for Assertions

func assertExpectedResult(t *testing.T, expected, actual string) {
	if expected != actual {
		t.Errorf("Expected result of \"%s\", but it was \"%s\" instead.", expected, actual)
	}
}

func assertError(t *testing.T, err error) {
	if err == nil {
		t.Errorf("Expected an error but received none.")
	}
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Test failed as an unexpected error occured.")
		log.Fatal(err)
	}
}
