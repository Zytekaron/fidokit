package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

func EncryptChaCha20(aead cipher.AEAD, data []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func DecryptChaCha20(aead cipher.AEAD, data []byte) ([]byte, error) {
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid data: too short for nonce and ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
