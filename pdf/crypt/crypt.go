// Package crypt provides PDF encryption and decryption.
package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
)

// Common errors
var (
	ErrInvalidPassword  = errors.New("invalid password")
	ErrUnsupportedCrypt = errors.New("unsupported encryption")
	ErrDecryptionFailed = errors.New("decryption failed")
)

// EncryptionVersion represents the PDF encryption version.
type EncryptionVersion int

const (
	EncryptionV1 EncryptionVersion = 1 // 40-bit RC4
	EncryptionV2 EncryptionVersion = 2 // Variable-bit RC4
	EncryptionV3 EncryptionVersion = 3 // Unpublished
	EncryptionV4 EncryptionVersion = 4 // AES-128 or variable RC4
	EncryptionV5 EncryptionVersion = 5 // AES-256
)

// EncryptionRevision represents the encryption revision.
type EncryptionRevision int

const (
	RevisionR2 EncryptionRevision = 2 // V2, 40-bit
	RevisionR3 EncryptionRevision = 3 // V2/V3, variable
	RevisionR4 EncryptionRevision = 4 // V4
	RevisionR5 EncryptionRevision = 5 // V5
	RevisionR6 EncryptionRevision = 6 // V5 with extension
)

// Permissions represents PDF permissions.
type Permissions uint32

const (
	PermPrint            Permissions = 1 << 2
	PermModify           Permissions = 1 << 3
	PermCopy             Permissions = 1 << 4
	PermAnnotate         Permissions = 1 << 5
	PermFillForms        Permissions = 1 << 8
	PermAccessibility    Permissions = 1 << 9
	PermAssemble         Permissions = 1 << 10
	PermPrintHighQuality Permissions = 1 << 11
)

// SecurityHandler handles PDF encryption/decryption.
type SecurityHandler interface {
	// Authenticate authenticates with a password.
	Authenticate(password []byte) error
	// DecryptString decrypts a string.
	DecryptString(data []byte, objNum, genNum int) ([]byte, error)
	// DecryptStream decrypts a stream.
	DecryptStream(data []byte, objNum, genNum int) ([]byte, error)
	// EncryptString encrypts a string.
	EncryptString(data []byte, objNum, genNum int) ([]byte, error)
	// EncryptStream encrypts a stream.
	EncryptStream(data []byte, objNum, genNum int) ([]byte, error)
}

// StandardSecurityHandler implements the standard PDF security handler.
type StandardSecurityHandler struct {
	Version     EncryptionVersion
	Revision    EncryptionRevision
	KeyLength   int
	Permissions Permissions
	OwnerKey    []byte // O value
	UserKey     []byte // U value
	OwnerE      []byte // OE value (R6)
	UserE       []byte // UE value (R6)
	Perms       []byte // Perms value (R6)
	FileID      []byte

	encryptionKey []byte
	useAES        bool
}

// NewStandardSecurityHandler creates a new standard security handler.
func NewStandardSecurityHandler(version EncryptionVersion, revision EncryptionRevision, keyLength int) *StandardSecurityHandler {
	return &StandardSecurityHandler{
		Version:   version,
		Revision:  revision,
		KeyLength: keyLength,
	}
}

// SetOwnerKey sets the O value.
func (h *StandardSecurityHandler) SetOwnerKey(o []byte) {
	h.OwnerKey = o
}

// SetUserKey sets the U value.
func (h *StandardSecurityHandler) SetUserKey(u []byte) {
	h.UserKey = u
}

// SetFileID sets the file ID.
func (h *StandardSecurityHandler) SetFileID(id []byte) {
	h.FileID = id
}

// SetPermissions sets the permissions.
func (h *StandardSecurityHandler) SetPermissions(p Permissions) {
	h.Permissions = p
}

// SetUseAES sets whether to use AES encryption.
func (h *StandardSecurityHandler) SetUseAES(useAES bool) {
	h.useAES = useAES
}

// Authenticate implements SecurityHandler.
func (h *StandardSecurityHandler) Authenticate(password []byte) error {
	// Try user password first
	if h.authenticateUser(password) {
		return nil
	}

	// Try owner password
	if h.authenticateOwner(password) {
		return nil
	}

	// Try empty password
	if h.authenticateUser(nil) {
		return nil
	}

	return ErrInvalidPassword
}

// authenticateUser tries to authenticate with user password.
func (h *StandardSecurityHandler) authenticateUser(password []byte) bool {
	switch h.Revision {
	case RevisionR2:
		key := h.computeKeyR2R3R4(password)
		computed := h.computeUserKeyR2(key)
		if bytes.Equal(computed, h.UserKey) {
			h.encryptionKey = key
			return true
		}
	case RevisionR3, RevisionR4:
		key := h.computeKeyR2R3R4(password)
		computed := h.computeUserKeyR3R4(key)
		if bytes.Equal(computed[:16], h.UserKey[:16]) {
			h.encryptionKey = key
			return true
		}
	case RevisionR5, RevisionR6:
		if h.authenticateUserR5R6(password) {
			return true
		}
	}
	return false
}

// authenticateOwner tries to authenticate with owner password.
func (h *StandardSecurityHandler) authenticateOwner(password []byte) bool {
	switch h.Revision {
	case RevisionR2, RevisionR3, RevisionR4:
		userPassword := h.computeUserPasswordFromOwner(password)
		return h.authenticateUser(userPassword)
	case RevisionR5, RevisionR6:
		return h.authenticateOwnerR5R6(password)
	}
	return false
}

// computeKeyR2R3R4 computes the encryption key for R2/R3/R4.
func (h *StandardSecurityHandler) computeKeyR2R3R4(password []byte) []byte {
	// Pad password to 32 bytes
	padded := padPassword(password)

	hash := md5.New()
	hash.Write(padded)
	hash.Write(h.OwnerKey)

	// Permission bytes
	p := uint32(h.Permissions)
	hash.Write([]byte{byte(p), byte(p >> 8), byte(p >> 16), byte(p >> 24)})

	hash.Write(h.FileID)

	// R4: if not encrypting metadata
	// hash.Write([]byte{0xff, 0xff, 0xff, 0xff})

	key := hash.Sum(nil)

	// R3+: 50 rounds of MD5
	if h.Revision >= RevisionR3 {
		n := h.KeyLength / 8
		for i := 0; i < 50; i++ {
			hash := md5.Sum(key[:n])
			key = hash[:]
		}
		key = key[:n]
	} else {
		key = key[:5] // 40-bit
	}

	return key
}

// computeUserKeyR2 computes U for R2.
func (h *StandardSecurityHandler) computeUserKeyR2(key []byte) []byte {
	cipher, _ := rc4.NewCipher(key)
	result := make([]byte, 32)
	cipher.XORKeyStream(result, passwordPadding)
	return result
}

// computeUserKeyR3R4 computes U for R3/R4.
func (h *StandardSecurityHandler) computeUserKeyR3R4(key []byte) []byte {
	hash := md5.New()
	hash.Write(passwordPadding)
	hash.Write(h.FileID)
	intermediate := hash.Sum(nil)

	cipher, _ := rc4.NewCipher(key)
	cipher.XORKeyStream(intermediate, intermediate)

	// 19 more rounds
	for i := 1; i <= 19; i++ {
		newKey := make([]byte, len(key))
		for j := range key {
			newKey[j] = key[j] ^ byte(i)
		}
		cipher, _ := rc4.NewCipher(newKey)
		cipher.XORKeyStream(intermediate, intermediate)
	}

	// Pad to 32 bytes
	result := make([]byte, 32)
	copy(result, intermediate)
	return result
}

// computeUserPasswordFromOwner extracts user password from owner password.
func (h *StandardSecurityHandler) computeUserPasswordFromOwner(ownerPassword []byte) []byte {
	padded := padPassword(ownerPassword)
	hash := md5.Sum(padded)
	key := hash[:]

	if h.Revision >= RevisionR3 {
		n := h.KeyLength / 8
		for i := 0; i < 50; i++ {
			hash := md5.Sum(key[:n])
			key = hash[:]
		}
		key = key[:n]
	} else {
		key = key[:5]
	}

	userPassword := make([]byte, 32)
	copy(userPassword, h.OwnerKey)

	if h.Revision >= RevisionR3 {
		for i := 19; i >= 0; i-- {
			newKey := make([]byte, len(key))
			for j := range key {
				newKey[j] = key[j] ^ byte(i)
			}
			cipher, _ := rc4.NewCipher(newKey)
			cipher.XORKeyStream(userPassword, userPassword)
		}
	} else {
		cipher, _ := rc4.NewCipher(key)
		cipher.XORKeyStream(userPassword, userPassword)
	}

	return userPassword
}

// authenticateUserR5R6 authenticates user for R5/R6.
func (h *StandardSecurityHandler) authenticateUserR5R6(password []byte) bool {
	if len(h.UserKey) < 48 {
		return false
	}

	// Compute hash
	validationSalt := h.UserKey[32:40]
	keySalt := h.UserKey[40:48]

	hash := h.computeHashR5R6(password, validationSalt, nil)
	if !bytes.Equal(hash, h.UserKey[:32]) {
		return false
	}

	// Compute file encryption key
	keyHash := h.computeHashR5R6(password, keySalt, nil)

	// Decrypt UE
	if len(h.UserE) != 32 {
		return false
	}

	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return false
	}

	iv := make([]byte, 16)
	mode := cipher.NewCBCDecrypter(block, iv)

	h.encryptionKey = make([]byte, 32)
	mode.CryptBlocks(h.encryptionKey, h.UserE)

	return true
}

// authenticateOwnerR5R6 authenticates owner for R5/R6.
func (h *StandardSecurityHandler) authenticateOwnerR5R6(password []byte) bool {
	if len(h.OwnerKey) < 48 {
		return false
	}

	validationSalt := h.OwnerKey[32:40]
	keySalt := h.OwnerKey[40:48]

	hash := h.computeHashR5R6(password, validationSalt, h.UserKey[:48])
	if !bytes.Equal(hash, h.OwnerKey[:32]) {
		return false
	}

	keyHash := h.computeHashR5R6(password, keySalt, h.UserKey[:48])

	if len(h.OwnerE) != 32 {
		return false
	}

	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return false
	}

	iv := make([]byte, 16)
	mode := cipher.NewCBCDecrypter(block, iv)

	h.encryptionKey = make([]byte, 32)
	mode.CryptBlocks(h.encryptionKey, h.OwnerE)

	return true
}

// computeHashR5R6 computes the hash for R5/R6.
func (h *StandardSecurityHandler) computeHashR5R6(password, salt, u []byte) []byte {
	// Initial hash
	hash := sha256.New()
	hash.Write(password)
	hash.Write(salt)
	if u != nil {
		hash.Write(u)
	}
	k := hash.Sum(nil)

	if h.Revision == RevisionR5 {
		return k
	}

	// R6: extended hash
	data := make([]byte, 0, 64*(len(password)+len(k)+48))
	for round := 0; round < 64 || round < int(data[len(data)-1])+32; round++ {
		k1 := bytes.Repeat(append(append(password, k...), u...), 64)

		// AES-128 CBC encrypt
		block, _ := aes.NewCipher(k[:16])
		iv := k[16:32]
		mode := cipher.NewCBCEncrypter(block, iv)

		e := make([]byte, len(k1))
		mode.CryptBlocks(e, k1)

		// Determine which hash to use
		sum := 0
		for _, b := range e[:16] {
			sum += int(b)
		}

		var hash2 []byte
		switch sum % 3 {
		case 0:
			h := sha256.Sum256(e)
			hash2 = h[:]
		case 1:
			h := sha512.New384()
			h.Write(e)
			hash2 = h.Sum(nil)
		case 2:
			h := sha512.Sum512(e)
			hash2 = h[:]
		}

		k = hash2[:32]
		data = e
	}

	return k[:32]
}

// DecryptString implements SecurityHandler.
func (h *StandardSecurityHandler) DecryptString(data []byte, objNum, genNum int) ([]byte, error) {
	if h.encryptionKey == nil {
		return nil, ErrInvalidPassword
	}

	key := h.computeObjectKey(objNum, genNum, false)
	return h.decrypt(data, key)
}

// DecryptStream implements SecurityHandler.
func (h *StandardSecurityHandler) DecryptStream(data []byte, objNum, genNum int) ([]byte, error) {
	if h.encryptionKey == nil {
		return nil, ErrInvalidPassword
	}

	key := h.computeObjectKey(objNum, genNum, true)
	return h.decrypt(data, key)
}

// EncryptString implements SecurityHandler.
func (h *StandardSecurityHandler) EncryptString(data []byte, objNum, genNum int) ([]byte, error) {
	if h.encryptionKey == nil {
		return nil, ErrInvalidPassword
	}

	key := h.computeObjectKey(objNum, genNum, false)
	return h.encrypt(data, key)
}

// EncryptStream implements SecurityHandler.
func (h *StandardSecurityHandler) EncryptStream(data []byte, objNum, genNum int) ([]byte, error) {
	if h.encryptionKey == nil {
		return nil, ErrInvalidPassword
	}

	key := h.computeObjectKey(objNum, genNum, true)
	return h.encrypt(data, key)
}

// computeObjectKey computes the key for a specific object.
func (h *StandardSecurityHandler) computeObjectKey(objNum, genNum int, isStream bool) []byte {
	if h.Revision >= RevisionR5 {
		return h.encryptionKey
	}

	hash := md5.New()
	hash.Write(h.encryptionKey)
	hash.Write([]byte{byte(objNum), byte(objNum >> 8), byte(objNum >> 16)})
	hash.Write([]byte{byte(genNum), byte(genNum >> 8)})

	if h.useAES {
		hash.Write([]byte("sAlT"))
	}

	key := hash.Sum(nil)

	keyLen := len(h.encryptionKey) + 5
	if keyLen > 16 {
		keyLen = 16
	}

	return key[:keyLen]
}

// decrypt decrypts data.
func (h *StandardSecurityHandler) decrypt(data, key []byte) ([]byte, error) {
	if h.useAES || h.Revision >= RevisionR5 {
		return h.decryptAES(data, key)
	}
	return h.decryptRC4(data, key)
}

// encrypt encrypts data.
func (h *StandardSecurityHandler) encrypt(data, key []byte) ([]byte, error) {
	if h.useAES || h.Revision >= RevisionR5 {
		return h.encryptAES(data, key)
	}
	return h.encryptRC4(data, key)
}

// decryptRC4 decrypts using RC4.
func (h *StandardSecurityHandler) decryptRC4(data, key []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(data))
	cipher.XORKeyStream(result, data)
	return result, nil
}

// encryptRC4 encrypts using RC4.
func (h *StandardSecurityHandler) encryptRC4(data, key []byte) ([]byte, error) {
	return h.decryptRC4(data, key) // RC4 is symmetric
}

// decryptAES decrypts using AES-CBC.
func (h *StandardSecurityHandler) decryptAES(data, key []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, ErrDecryptionFailed
	}

	iv := data[:16]
	ciphertext := data[16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	if len(plaintext) == 0 {
		return plaintext, nil
	}

	padLen := int(plaintext[len(plaintext)-1])
	if padLen > 16 || padLen > len(plaintext) {
		return plaintext, nil // Invalid padding, return as-is
	}

	return plaintext[:len(plaintext)-padLen], nil
}

// encryptAES encrypts using AES-CBC.
func (h *StandardSecurityHandler) encryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Add PKCS7 padding
	padLen := 16 - len(data)%16
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	// Generate IV
	iv := make([]byte, 16)
	// In production, use crypto/rand

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return append(iv, ciphertext...), nil
}

// Password padding constant (32 bytes).
var passwordPadding = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
	0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
	0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// padPassword pads a password to 32 bytes.
func padPassword(password []byte) []byte {
	result := make([]byte, 32)
	copy(result, password)
	if len(password) < 32 {
		copy(result[len(password):], passwordPadding)
	}
	return result
}

// CreateEncryptDict creates an encryption dictionary.
func CreateEncryptDict(handler *StandardSecurityHandler) map[string]interface{} {
	dict := map[string]interface{}{
		"Filter": "Standard",
		"V":      int(handler.Version),
		"R":      int(handler.Revision),
		"Length": handler.KeyLength,
		"O":      handler.OwnerKey,
		"U":      handler.UserKey,
		"P":      int32(handler.Permissions),
	}

	if handler.Revision >= RevisionR5 {
		dict["OE"] = handler.OwnerE
		dict["UE"] = handler.UserE
		dict["Perms"] = handler.Perms
	}

	return dict
}
