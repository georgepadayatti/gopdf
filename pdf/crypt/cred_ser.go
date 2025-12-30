// Package crypt provides PDF encryption and decryption.
// This file implements credential serialization for PDF security handlers.
package crypt

import (
	"errors"
	"fmt"
	"sync"
)

// Credential serialization errors
var (
	ErrCredentialNotRegistered   = errors.New("credential type not registered")
	ErrCredentialSerialization   = errors.New("credential serialization error")
	ErrCredentialDeserialization = errors.New("credential deserialization error")
)

// SerialisedCredential represents a credential in serialized form.
type SerialisedCredential struct {
	// CredentialType is the registered type name of the credential.
	CredentialType string

	// Data is the credential data as a byte string.
	Data []byte
}

// NewSerialisedCredential creates a new serialized credential.
func NewSerialisedCredential(credentialType string, data []byte) *SerialisedCredential {
	return &SerialisedCredential{
		CredentialType: credentialType,
		Data:           data,
	}
}

// SerialisableCredential is the interface for credentials that can be serialized.
type SerialisableCredential interface {
	// GetName returns the type name of the credential.
	GetName() string

	// SerialiseValue serializes the credential to raw binary data.
	SerialiseValue() ([]byte, error)
}

// CredentialDeserializer is a function that deserializes credential data.
type CredentialDeserializer func(data []byte) (SerialisableCredential, error)

// credentialRegistry holds registered credential types.
type credentialRegistry struct {
	mu            sync.RWMutex
	deserializers map[string]CredentialDeserializer
}

// global credential registry
var registry = &credentialRegistry{
	deserializers: make(map[string]CredentialDeserializer),
}

// RegisterCredentialType registers a credential type with its deserializer.
// This should be called during package initialization.
func RegisterCredentialType(name string, deserializer CredentialDeserializer) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.deserializers[name] = deserializer
}

// UnregisterCredentialType removes a credential type from the registry.
// Primarily useful for testing.
func UnregisterCredentialType(name string) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	delete(registry.deserializers, name)
}

// IsCredentialTypeRegistered checks if a credential type is registered.
func IsCredentialTypeRegistered(name string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	_, ok := registry.deserializers[name]
	return ok
}

// GetRegisteredCredentialTypes returns a list of all registered credential type names.
func GetRegisteredCredentialTypes() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	names := make([]string, 0, len(registry.deserializers))
	for name := range registry.deserializers {
		names = append(names, name)
	}
	return names
}

// Deserialise deserializes a SerialisedCredential by looking up the proper
// deserializer and invoking it.
func Deserialise(ser *SerialisedCredential) (SerialisableCredential, error) {
	if ser == nil {
		return nil, fmt.Errorf("%w: nil credential", ErrCredentialDeserialization)
	}

	registry.mu.RLock()
	deserializer, ok := registry.deserializers[ser.CredentialType]
	registry.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: credential type '%s' not known",
			ErrCredentialNotRegistered, ser.CredentialType)
	}

	cred, err := deserializer(ser.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialDeserialization, err)
	}

	return cred, nil
}

// Serialise serializes a SerialisableCredential to a SerialisedCredential.
func Serialise(cred SerialisableCredential) (*SerialisedCredential, error) {
	if cred == nil {
		return nil, fmt.Errorf("%w: nil credential", ErrCredentialSerialization)
	}

	data, err := cred.SerialiseValue()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialSerialization, err)
	}

	return &SerialisedCredential{
		CredentialType: cred.GetName(),
		Data:           data,
	}, nil
}

// PasswordCredential is a simple credential containing a password.
type PasswordCredential struct {
	Password []byte
}

// GetName returns the credential type name.
func (c *PasswordCredential) GetName() string {
	return "password"
}

// SerialiseValue serializes the password credential.
func (c *PasswordCredential) SerialiseValue() ([]byte, error) {
	if c.Password == nil {
		return []byte{}, nil
	}
	// Make a copy to avoid external modification
	result := make([]byte, len(c.Password))
	copy(result, c.Password)
	return result, nil
}

// NewPasswordCredential creates a new password credential.
func NewPasswordCredential(password []byte) *PasswordCredential {
	return &PasswordCredential{Password: password}
}

// deserializePasswordCredential deserializes a password credential.
func deserializePasswordCredential(data []byte) (SerialisableCredential, error) {
	password := make([]byte, len(data))
	copy(password, data)
	return &PasswordCredential{Password: password}, nil
}

// FileEncryptionKeyCredential holds the raw file encryption key.
// This allows compatibility with any security handler.
type FileEncryptionKeyCredential struct {
	Key []byte
}

// GetName returns the credential type name.
func (c *FileEncryptionKeyCredential) GetName() string {
	return "file_encryption_key"
}

// SerialiseValue serializes the file encryption key credential.
func (c *FileEncryptionKeyCredential) SerialiseValue() ([]byte, error) {
	if c.Key == nil {
		return nil, fmt.Errorf("file encryption key is nil")
	}
	result := make([]byte, len(c.Key))
	copy(result, c.Key)
	return result, nil
}

// NewFileEncryptionKeyCredential creates a new file encryption key credential.
func NewFileEncryptionKeyCredential(key []byte) *FileEncryptionKeyCredential {
	return &FileEncryptionKeyCredential{Key: key}
}

// deserializeFileEncryptionKeyCredential deserializes a file encryption key credential.
func deserializeFileEncryptionKeyCredential(data []byte) (SerialisableCredential, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty file encryption key")
	}
	key := make([]byte, len(data))
	copy(key, data)
	return &FileEncryptionKeyCredential{Key: key}, nil
}

// Register built-in credential types during package initialization.
func init() {
	RegisterCredentialType("password", deserializePasswordCredential)
	RegisterCredentialType("file_encryption_key", deserializeFileEncryptionKeyCredential)
}

// CredentialStore provides storage and retrieval of serialized credentials.
type CredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]*SerialisedCredential
}

// NewCredentialStore creates a new credential store.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		credentials: make(map[string]*SerialisedCredential),
	}
}

// Store stores a serialized credential with the given key.
func (s *CredentialStore) Store(key string, cred *SerialisedCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[key] = cred
}

// StoreCredential serializes and stores a credential.
func (s *CredentialStore) StoreCredential(key string, cred SerialisableCredential) error {
	ser, err := Serialise(cred)
	if err != nil {
		return err
	}
	s.Store(key, ser)
	return nil
}

// Load retrieves a serialized credential by key.
func (s *CredentialStore) Load(key string) (*SerialisedCredential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cred, ok := s.credentials[key]
	return cred, ok
}

// LoadAndDeserialize retrieves and deserializes a credential by key.
func (s *CredentialStore) LoadAndDeserialize(key string) (SerialisableCredential, error) {
	ser, ok := s.Load(key)
	if !ok {
		return nil, fmt.Errorf("credential not found: %s", key)
	}
	return Deserialise(ser)
}

// Delete removes a credential from the store.
func (s *CredentialStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.credentials, key)
}

// Keys returns all keys in the store.
func (s *CredentialStore) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.credentials))
	for k := range s.credentials {
		keys = append(keys, k)
	}
	return keys
}

// Clear removes all credentials from the store.
func (s *CredentialStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials = make(map[string]*SerialisedCredential)
}

// Count returns the number of credentials in the store.
func (s *CredentialStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.credentials)
}
