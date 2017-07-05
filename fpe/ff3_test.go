package fpe

import (
	"testing"
)

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

func TestFF3Encrypt1(t *testing.T) {
	t.Log("Testing FF3 encryption (case 1)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "750918814058654607", msg)
}

func TestFF3Decrypt1(t *testing.T) {
	t.Log("Testing FF3 decryption (case 1)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("750918814058654607", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt2(t *testing.T) {
	t.Log("Testing FF3 encryption (case 2)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "018989839189395384", msg)
}

func TestFF3Decrypt2(t *testing.T) {
	t.Log("Testing FF3 decryption (case 2)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("018989839189395384", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt3(t *testing.T) {
	t.Log("Testing FF3 encryption (case 3)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "48598367162252569629397416226", msg)
}

func TestFF3Decrypt3(t *testing.T) {
	t.Log("Testing FF3 decryption (case 3)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("48598367162252569629397416226", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt4(t *testing.T) {
	t.Log("Testing FF3 encryption (case 4)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "34695224821734535122613701434", msg)
}

func TestFF3Decrypt4(t *testing.T) {
	t.Log("Testing FF3 decryption (case 4)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("34695224821734535122613701434", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt5(t *testing.T) {
	t.Log("Testing FF3 encryption (case 5)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 26, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("0123456789abcdefghi", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "g2pk40i992fn20cjakb", msg)
}

func TestFF3Decrypt5(t *testing.T) {
	t.Log("Testing FF3 decryption (case 5)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 26, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("g2pk40i992fn20cjakb", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF3Encrypt6(t *testing.T) {
	t.Log("Testing FF3 encryption (case 6)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "646965393875028755", msg)
}

func TestFF3Decrypt6(t *testing.T) {
	t.Log("Testing FF3 decryption (case 6)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("646965393875028755", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt7(t *testing.T) {
	t.Log("Testing FF3 encryption (case 7)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "961610514491424446", msg)
}

func TestFF3Decrypt7(t *testing.T) {
	t.Log("Testing FF3 decryption (case 7)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("961610514491424446", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt8(t *testing.T) {
	t.Log("Testing FF3 encryption (case 8)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "53048884065350204541786380807", msg)
}

func TestFF3Decrypt8(t *testing.T) {
	t.Log("Testing FF3 decryption (case 8)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("53048884065350204541786380807", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt9(t *testing.T) {
	t.Log("Testing FF3 encryption (case 9)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "98083802678820389295041483512", msg)
}

func TestFF3Decrypt9(t *testing.T) {
	t.Log("Testing FF3 decryption (case 9)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("98083802678820389295041483512", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt10(t *testing.T) {
	t.Log("Testing FF3 encryption (case 10)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 26, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("0123456789abcdefghi", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "i0ihe2jfj7a9opf9p88", msg)
}

func TestFF3Decrypt10(t *testing.T) {
	t.Log("Testing FF3 decryption (case 10)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6", 26, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("i0ihe2jfj7a9opf9p88", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF3Encrypt11(t *testing.T) {
	t.Log("Testing FF3 encryption (case 11)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "922011205562777495", msg)
}

func TestFF3Decrypt11(t *testing.T) {
	t.Log("Testing FF3 decryption (case 11)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("922011205562777495", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt12(t *testing.T) {
	t.Log("Testing FF3 encryption (case 12)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("890121234567890000", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "504149865578056140", msg)
}

func TestFF3Decrypt12(t *testing.T) {
	t.Log("Testing FF3 decryption (case 12)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 20)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("504149865578056140", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "890121234567890000", plaintext)
}

func TestFF3Encrypt13(t *testing.T) {
	t.Log("Testing FF3 encryption (case 13)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "04344343235792599165734622699", msg)
}

func TestFF3Decrypt13(t *testing.T) {
	t.Log("Testing FF3 decryption (case 13)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("04344343235792599165734622699", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt14(t *testing.T) {
	t.Log("Testing FF3 encryption (case 14)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("89012123456789000000789000000", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "30859239999374053872365555822", msg)
}

func TestFF3Decrypt14(t *testing.T) {
	t.Log("Testing FF3 decryption (case 14)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 10, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("30859239999374053872365555822", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	assertNoError(t, err)
	assertExpectedResult(t, "89012123456789000000789000000", plaintext)
}

func TestFF3Encrypt15(t *testing.T) {
	t.Log("Testing FF3 encryption (case 15)... ")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 26, 2, 30)
	assertNoError(t, err)
	msg, err := ff3.Encrypt("0123456789abcdefghi", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "p0b2godfja9bhb7bk38", msg)
}

func TestFF3Decrypt15(t *testing.T) {
	t.Log("Testing FF3 decryption (case 15)...")
	ff3, err := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C", 26, 2, 30)
	assertNoError(t, err)
	plaintext, err := ff3.Decrypt("p0b2godfja9bhb7bk38", []byte{0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8})
	assertNoError(t, err)
	assertExpectedResult(t, "0123456789abcdefghi", plaintext)
}

func TestFF3EncryptNoMessage(t *testing.T) {
	t.Log("Testing FF3 encryption with no message... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 2, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3DecryptNoMessage(t *testing.T) {
	t.Log("Testing FF3 decryption with no message... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 2, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3EncryptShortMessage(t *testing.T) {
	t.Log("Testing FF3 encryption with message that is too short... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("1234", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3DecryptShortMessage(t *testing.T) {
	t.Log("Testing FF3 decryption with message that is too short... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("1234", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3EncryptInvalidTweak(t *testing.T) {
	t.Log("Testing FF3 encryption with tweak that is not 8 bytes... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("12345", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73, 0x74})
	assertError(t, err)
}

func TestFF3DecryptInvalidTweak(t *testing.T) {
	t.Log("Testing FF3 decryption with tweak that is not 8 bytes... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("12345", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73, 0x74})
	assertError(t, err)
}

func TestFF3EncryptLongMessage(t *testing.T) {
	t.Log("Testing FF3 encryption with message that is too long... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("123456789012345678901", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3DecryptLongMessage(t *testing.T) {
	t.Log("Testing FF3 decryption with message that is too long... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("123456789012345678901", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3EncryptMessageTooLongForBlock(t *testing.T) {
	t.Log("Testing FF3 encryption with message that is too long for the block calculation... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 36)
	assertNoError(t, err)
	_, err = ff3.Encrypt("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3DecryptMessageTooLongForBlock(t *testing.T) {
	t.Log("Testing FF3 decryption with message that is too long for the block calculation... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 36, 5, 36)
	assertNoError(t, err)
	_, err = ff3.Decrypt("1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73})
	assertError(t, err)
}

func TestFF3EncryptInvalidMessage1(t *testing.T) {
	t.Log("Testing FF3 encryption with invalid message (case 1)... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("12345ABCDE", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73})
	assertError(t, err)
}

func TestFF3DecryptInvalidMessage1(t *testing.T) {
	t.Log("Testing FF3 decryption with invalid message (case 1)... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("12345ABCDE", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73})
	assertError(t, err)
}

func TestFF3EncryptInvalidMessage2(t *testing.T) {
	t.Log("Testing FF3 encryption with invalid message (case 2)... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Encrypt("JK12345", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73})
	assertError(t, err)
}

func TestFF3DecryptInvalidMessage2(t *testing.T) {
	t.Log("Testing FF3 decryption with invalid message (case 2)... ")
	ff3, err := NewFF3("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", 10, 5, 20)
	assertNoError(t, err)
	_, err = ff3.Decrypt("JK12345", []byte{0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73})
	assertError(t, err)
}

func BenchmarkFF3Encrypt(b *testing.B) {
	ff3, _ := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	tweak := []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73}

	for i := 0; i < b.N; i++ {
		ff3.Encrypt("890121234567890000", tweak)
	}
}

func BenchmarkFF3Decrypt(b *testing.B) {
	ff3, _ := NewFF3("EF4359D8D580AA4F7F036D6F04FC6A94", 10, 2, 20)
	tweak := []byte{0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73}

	for i := 0; i < b.N; i++ {
		ff3.Decrypt("750918814058654607", tweak)
	}
}
