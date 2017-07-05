package fpe

type Algorithm interface {
	Encrypt(plaintext string, tweak []byte) (message string, err error)
	Decrypt(message string, tweak []byte) (plaintext string, err error)
}
