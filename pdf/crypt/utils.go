// Package crypt provides encryption utility functions.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"hash"
)

var (
	ErrInvalidPadding   = errors.New("invalid PKCS7 padding")
	ErrInvalidBlockSize = errors.New("data not multiple of block size")
	ErrInvalidKeyLength = errors.New("invalid key length")
)

// RC4Encrypt encrypts data using RC4.
func RC4Encrypt(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(data))
	c.XORKeyStream(result, data)
	return result, nil
}

// RC4Decrypt decrypts data using RC4 (same as encrypt for RC4).
func RC4Decrypt(key, data []byte) ([]byte, error) {
	return RC4Encrypt(key, data)
}

// AESCBCEncrypt encrypts data using AES-CBC with PKCS7 padding.
// If iv is nil, a random IV is generated.
// Returns the IV concatenated with the ciphertext.
func AESCBCEncrypt(key, data, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if iv == nil {
		iv = make([]byte, aes.BlockSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
	}

	// Apply PKCS7 padding
	padded := PKCS7Pad(data, aes.BlockSize)

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Return IV + ciphertext
	return append(iv, ciphertext...), nil
}

// AESCBCDecrypt decrypts AES-CBC encrypted data with PKCS7 padding.
// Expects IV to be prepended to ciphertext.
func AESCBCDecrypt(key, data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	return PKCS7Unpad(plaintext)
}

// AESCBCDecryptWithIV decrypts AES-CBC encrypted data with explicit IV.
func AESCBCDecryptWithIV(key, data, iv []byte, usePadding bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, data)

	if usePadding && len(plaintext) > 0 {
		return PKCS7Unpad(plaintext)
	}
	return plaintext, nil
}

// TripleDESDecrypt decrypts data using Triple DES CBC.
func TripleDESDecrypt(key, data, iv []byte) ([]byte, error) {
	if len(key) != 24 {
		return nil, ErrInvalidKeyLength
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%block.BlockSize() != 0 {
		return nil, ErrInvalidBlockSize
	}

	plaintext := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, data)

	return PKCS7Unpad(plaintext)
}

// PKCS7Pad adds PKCS7 padding to data.
func PKCS7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(padLen)
	}
	return append(data, padding...)
}

// PKCS7Unpad removes PKCS7 padding from data.
func PKCS7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > 16 || padLen > len(data) {
		// Invalid padding, return as-is
		return data, nil
	}

	// Verify padding
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return data, nil // Invalid padding, return as-is
		}
	}

	return data[:len(data)-padLen], nil
}

// DeriveObjectKey derives the per-object encryption key.
// This is Algorithm 1 from PDF 1.7 specification.
func DeriveObjectKey(fileKey []byte, objNum, genNum int, useAES bool) []byte {
	// Compute object-specific key
	h := md5.New()
	h.Write(fileKey)
	h.Write([]byte{byte(objNum), byte(objNum >> 8), byte(objNum >> 16)})
	h.Write([]byte{byte(genNum), byte(genNum >> 8)})

	if useAES {
		h.Write([]byte("sAlT"))
	}

	key := h.Sum(nil)

	// Key length is min(fileKey + 5, 16)
	keyLen := len(fileKey) + 5
	if keyLen > 16 {
		keyLen = 16
	}

	return key[:keyLen]
}

// NewMD5 returns a new MD5 hash.
func NewMD5() hash.Hash {
	return md5.New()
}

// CryptFilterType represents the type of crypt filter.
type CryptFilterType string

const (
	CryptFilterNone     CryptFilterType = "None"
	CryptFilterV2       CryptFilterType = "V2"       // RC4
	CryptFilterAESV2    CryptFilterType = "AESV2"    // AES-128
	CryptFilterAESV3    CryptFilterType = "AESV3"    // AES-256
	CryptFilterIdentity CryptFilterType = "Identity" // No encryption
)

// CryptFilter represents a PDF crypt filter.
type CryptFilter struct {
	// Type is the crypt filter type.
	Type CryptFilterType

	// KeyLength is the key length in bytes.
	KeyLength int

	// AuthEvent specifies when authentication occurs.
	AuthEvent string

	// Recipients for public key encryption.
	Recipients [][]byte
}

// NewCryptFilter creates a new crypt filter.
func NewCryptFilter(filterType CryptFilterType, keyLength int) *CryptFilter {
	return &CryptFilter{
		Type:      filterType,
		KeyLength: keyLength,
		AuthEvent: "DocOpen",
	}
}

// Encrypt encrypts data using the filter's algorithm.
func (f *CryptFilter) Encrypt(key, data []byte) ([]byte, error) {
	switch f.Type {
	case CryptFilterNone, CryptFilterIdentity:
		return data, nil
	case CryptFilterV2:
		return RC4Encrypt(key, data)
	case CryptFilterAESV2, CryptFilterAESV3:
		return AESCBCEncrypt(key, data, nil)
	default:
		return nil, ErrUnsupportedCrypt
	}
}

// Decrypt decrypts data using the filter's algorithm.
func (f *CryptFilter) Decrypt(key, data []byte) ([]byte, error) {
	switch f.Type {
	case CryptFilterNone, CryptFilterIdentity:
		return data, nil
	case CryptFilterV2:
		return RC4Decrypt(key, data)
	case CryptFilterAESV2, CryptFilterAESV3:
		return AESCBCDecrypt(key, data)
	default:
		return nil, ErrUnsupportedCrypt
	}
}
