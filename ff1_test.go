package fpe

import (
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
