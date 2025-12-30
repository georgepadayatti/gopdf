package crypt

import (
	"bytes"
	"strings"
	"testing"
)

func TestSerialisedCredential(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		cred := NewSerialisedCredential("test_type", []byte("test_data"))

		if cred.CredentialType != "test_type" {
			t.Errorf("CredentialType = %q, want test_type", cred.CredentialType)
		}

		if !bytes.Equal(cred.Data, []byte("test_data")) {
			t.Error("Data mismatch")
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		cred := NewSerialisedCredential("empty", nil)

		if cred.CredentialType != "empty" {
			t.Errorf("CredentialType = %q, want empty", cred.CredentialType)
		}

		if cred.Data != nil {
			t.Error("Data should be nil")
		}
	})
}

func TestPasswordCredential(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		cred := NewPasswordCredential([]byte("secret"))

		if cred.GetName() != "password" {
			t.Errorf("GetName() = %q, want password", cred.GetName())
		}

		if !bytes.Equal(cred.Password, []byte("secret")) {
			t.Error("Password mismatch")
		}
	})

	t.Run("Serialize", func(t *testing.T) {
		cred := NewPasswordCredential([]byte("secret"))

		data, err := cred.SerialiseValue()
		if err != nil {
			t.Fatalf("SerialiseValue failed: %v", err)
		}

		if !bytes.Equal(data, []byte("secret")) {
			t.Error("Serialized data mismatch")
		}
	})

	t.Run("SerializeNil", func(t *testing.T) {
		cred := NewPasswordCredential(nil)

		data, err := cred.SerialiseValue()
		if err != nil {
			t.Fatalf("SerialiseValue failed: %v", err)
		}

		if len(data) != 0 {
			t.Error("Serialized data should be empty")
		}
	})

	t.Run("SerializeAndDeserialize", func(t *testing.T) {
		original := NewPasswordCredential([]byte("my_password"))

		ser, err := Serialise(original)
		if err != nil {
			t.Fatalf("Serialise failed: %v", err)
		}

		if ser.CredentialType != "password" {
			t.Errorf("CredentialType = %q, want password", ser.CredentialType)
		}

		deser, err := Deserialise(ser)
		if err != nil {
			t.Fatalf("Deserialise failed: %v", err)
		}

		pwCred, ok := deser.(*PasswordCredential)
		if !ok {
			t.Fatalf("Expected *PasswordCredential, got %T", deser)
		}

		if !bytes.Equal(pwCred.Password, original.Password) {
			t.Error("Password mismatch after deserialize")
		}
	})
}

func TestFileEncryptionKeyCredential(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}

		cred := NewFileEncryptionKeyCredential(key)

		if cred.GetName() != "file_encryption_key" {
			t.Errorf("GetName() = %q, want file_encryption_key", cred.GetName())
		}

		if !bytes.Equal(cred.Key, key) {
			t.Error("Key mismatch")
		}
	})

	t.Run("Serialize", func(t *testing.T) {
		key := []byte{1, 2, 3, 4, 5}
		cred := NewFileEncryptionKeyCredential(key)

		data, err := cred.SerialiseValue()
		if err != nil {
			t.Fatalf("SerialiseValue failed: %v", err)
		}

		if !bytes.Equal(data, key) {
			t.Error("Serialized data mismatch")
		}
	})

	t.Run("SerializeNil", func(t *testing.T) {
		cred := NewFileEncryptionKeyCredential(nil)

		_, err := cred.SerialiseValue()
		if err == nil {
			t.Error("Expected error for nil key")
		}
	})

	t.Run("SerializeAndDeserialize", func(t *testing.T) {
		key := []byte{0x10, 0x20, 0x30, 0x40}
		original := NewFileEncryptionKeyCredential(key)

		ser, err := Serialise(original)
		if err != nil {
			t.Fatalf("Serialise failed: %v", err)
		}

		deser, err := Deserialise(ser)
		if err != nil {
			t.Fatalf("Deserialise failed: %v", err)
		}

		keyCred, ok := deser.(*FileEncryptionKeyCredential)
		if !ok {
			t.Fatalf("Expected *FileEncryptionKeyCredential, got %T", deser)
		}

		if !bytes.Equal(keyCred.Key, original.Key) {
			t.Error("Key mismatch after deserialize")
		}
	})
}

func TestCredentialRegistry(t *testing.T) {
	t.Run("BuiltInTypes", func(t *testing.T) {
		if !IsCredentialTypeRegistered("password") {
			t.Error("password type should be registered")
		}

		if !IsCredentialTypeRegistered("file_encryption_key") {
			t.Error("file_encryption_key type should be registered")
		}
	})

	t.Run("UnknownType", func(t *testing.T) {
		if IsCredentialTypeRegistered("unknown_type") {
			t.Error("unknown_type should not be registered")
		}
	})

	t.Run("GetRegisteredTypes", func(t *testing.T) {
		types := GetRegisteredCredentialTypes()

		if len(types) < 2 {
			t.Errorf("Expected at least 2 types, got %d", len(types))
		}

		hasPassword := false
		hasFileKey := false
		for _, typ := range types {
			if typ == "password" {
				hasPassword = true
			}
			if typ == "file_encryption_key" {
				hasFileKey = true
			}
		}

		if !hasPassword {
			t.Error("password type not in registered types")
		}
		if !hasFileKey {
			t.Error("file_encryption_key type not in registered types")
		}
	})

	t.Run("RegisterAndUnregister", func(t *testing.T) {
		// Register a custom type
		RegisterCredentialType("custom_test", func(data []byte) (SerialisableCredential, error) {
			return NewPasswordCredential(data), nil
		})

		if !IsCredentialTypeRegistered("custom_test") {
			t.Error("custom_test should be registered")
		}

		// Unregister
		UnregisterCredentialType("custom_test")

		if IsCredentialTypeRegistered("custom_test") {
			t.Error("custom_test should be unregistered")
		}
	})
}

func TestDeserialise(t *testing.T) {
	t.Run("NilCredential", func(t *testing.T) {
		_, err := Deserialise(nil)
		if err == nil {
			t.Error("Expected error for nil credential")
		}
	})

	t.Run("UnknownType", func(t *testing.T) {
		ser := NewSerialisedCredential("unknown_type_xyz", []byte("data"))

		_, err := Deserialise(ser)
		if err == nil {
			t.Error("Expected error for unknown type")
		}

		if !strings.Contains(err.Error(), "not known") {
			t.Errorf("Error should mention 'not known': %v", err)
		}
	})

	t.Run("ValidPassword", func(t *testing.T) {
		ser := NewSerialisedCredential("password", []byte("test_pass"))

		cred, err := Deserialise(ser)
		if err != nil {
			t.Fatalf("Deserialise failed: %v", err)
		}

		pwCred, ok := cred.(*PasswordCredential)
		if !ok {
			t.Fatalf("Expected *PasswordCredential, got %T", cred)
		}

		if !bytes.Equal(pwCred.Password, []byte("test_pass")) {
			t.Error("Password mismatch")
		}
	})
}

func TestSerialise(t *testing.T) {
	t.Run("NilCredential", func(t *testing.T) {
		_, err := Serialise(nil)
		if err == nil {
			t.Error("Expected error for nil credential")
		}
	})

	t.Run("ValidCredential", func(t *testing.T) {
		cred := NewPasswordCredential([]byte("pass"))

		ser, err := Serialise(cred)
		if err != nil {
			t.Fatalf("Serialise failed: %v", err)
		}

		if ser.CredentialType != "password" {
			t.Errorf("CredentialType = %q, want password", ser.CredentialType)
		}

		if !bytes.Equal(ser.Data, []byte("pass")) {
			t.Error("Data mismatch")
		}
	})
}

func TestCredentialStore(t *testing.T) {
	t.Run("Create", func(t *testing.T) {
		store := NewCredentialStore()
		if store == nil {
			t.Fatal("Store is nil")
		}

		if store.Count() != 0 {
			t.Errorf("Count = %d, want 0", store.Count())
		}
	})

	t.Run("StoreAndLoad", func(t *testing.T) {
		store := NewCredentialStore()

		ser := NewSerialisedCredential("password", []byte("secret"))
		store.Store("key1", ser)

		loaded, ok := store.Load("key1")
		if !ok {
			t.Fatal("Credential not found")
		}

		if loaded.CredentialType != "password" {
			t.Error("CredentialType mismatch")
		}

		if !bytes.Equal(loaded.Data, []byte("secret")) {
			t.Error("Data mismatch")
		}
	})

	t.Run("LoadNotFound", func(t *testing.T) {
		store := NewCredentialStore()

		_, ok := store.Load("nonexistent")
		if ok {
			t.Error("Should not find nonexistent key")
		}
	})

	t.Run("StoreCredential", func(t *testing.T) {
		store := NewCredentialStore()

		cred := NewPasswordCredential([]byte("my_pass"))
		err := store.StoreCredential("user1", cred)
		if err != nil {
			t.Fatalf("StoreCredential failed: %v", err)
		}

		loaded, ok := store.Load("user1")
		if !ok {
			t.Fatal("Credential not found")
		}

		if loaded.CredentialType != "password" {
			t.Error("CredentialType mismatch")
		}
	})

	t.Run("LoadAndDeserialize", func(t *testing.T) {
		store := NewCredentialStore()

		original := NewPasswordCredential([]byte("test123"))
		store.StoreCredential("test_key", original)

		cred, err := store.LoadAndDeserialize("test_key")
		if err != nil {
			t.Fatalf("LoadAndDeserialize failed: %v", err)
		}

		pwCred, ok := cred.(*PasswordCredential)
		if !ok {
			t.Fatalf("Expected *PasswordCredential, got %T", cred)
		}

		if !bytes.Equal(pwCred.Password, []byte("test123")) {
			t.Error("Password mismatch")
		}
	})

	t.Run("LoadAndDeserializeNotFound", func(t *testing.T) {
		store := NewCredentialStore()

		_, err := store.LoadAndDeserialize("not_there")
		if err == nil {
			t.Error("Expected error for missing key")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		store := NewCredentialStore()

		store.Store("to_delete", NewSerialisedCredential("password", []byte("x")))

		if store.Count() != 1 {
			t.Errorf("Count = %d, want 1", store.Count())
		}

		store.Delete("to_delete")

		if store.Count() != 0 {
			t.Errorf("Count = %d, want 0", store.Count())
		}

		_, ok := store.Load("to_delete")
		if ok {
			t.Error("Should not find deleted key")
		}
	})

	t.Run("Keys", func(t *testing.T) {
		store := NewCredentialStore()

		store.Store("a", NewSerialisedCredential("password", nil))
		store.Store("b", NewSerialisedCredential("password", nil))
		store.Store("c", NewSerialisedCredential("password", nil))

		keys := store.Keys()
		if len(keys) != 3 {
			t.Errorf("len(Keys) = %d, want 3", len(keys))
		}

		// Check all keys are present
		keyMap := make(map[string]bool)
		for _, k := range keys {
			keyMap[k] = true
		}

		if !keyMap["a"] || !keyMap["b"] || !keyMap["c"] {
			t.Error("Not all keys present")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		store := NewCredentialStore()

		store.Store("x", NewSerialisedCredential("password", nil))
		store.Store("y", NewSerialisedCredential("password", nil))

		if store.Count() != 2 {
			t.Errorf("Count = %d, want 2", store.Count())
		}

		store.Clear()

		if store.Count() != 0 {
			t.Errorf("Count = %d, want 0", store.Count())
		}
	})

	t.Run("Count", func(t *testing.T) {
		store := NewCredentialStore()

		if store.Count() != 0 {
			t.Errorf("Initial count = %d, want 0", store.Count())
		}

		store.Store("1", NewSerialisedCredential("password", nil))
		if store.Count() != 1 {
			t.Errorf("Count after 1 store = %d, want 1", store.Count())
		}

		store.Store("2", NewSerialisedCredential("password", nil))
		if store.Count() != 2 {
			t.Errorf("Count after 2 stores = %d, want 2", store.Count())
		}
	})
}

func TestCredentialErrors(t *testing.T) {
	if ErrCredentialNotRegistered.Error() == "" {
		t.Error("ErrCredentialNotRegistered should have a message")
	}

	if ErrCredentialSerialization.Error() == "" {
		t.Error("ErrCredentialSerialization should have a message")
	}

	if ErrCredentialDeserialization.Error() == "" {
		t.Error("ErrCredentialDeserialization should have a message")
	}
}

// Custom credential type for testing
type customCredential struct {
	Value string
}

func (c *customCredential) GetName() string {
	return "custom"
}

func (c *customCredential) SerialiseValue() ([]byte, error) {
	return []byte(c.Value), nil
}

func TestCustomCredentialType(t *testing.T) {
	// Register custom type
	RegisterCredentialType("custom", func(data []byte) (SerialisableCredential, error) {
		return &customCredential{Value: string(data)}, nil
	})
	defer UnregisterCredentialType("custom")

	// Create and serialize
	original := &customCredential{Value: "hello world"}

	ser, err := Serialise(original)
	if err != nil {
		t.Fatalf("Serialise failed: %v", err)
	}

	if ser.CredentialType != "custom" {
		t.Errorf("CredentialType = %q, want custom", ser.CredentialType)
	}

	// Deserialize
	deser, err := Deserialise(ser)
	if err != nil {
		t.Fatalf("Deserialise failed: %v", err)
	}

	customCred, ok := deser.(*customCredential)
	if !ok {
		t.Fatalf("Expected *customCredential, got %T", deser)
	}

	if customCred.Value != "hello world" {
		t.Errorf("Value = %q, want 'hello world'", customCred.Value)
	}
}

func TestDataCopyOnSerialize(t *testing.T) {
	// Test that serialization makes a copy of the data
	original := []byte("original")
	cred := NewPasswordCredential(original)

	data, _ := cred.SerialiseValue()

	// Modify original
	original[0] = 'X'

	// Serialized data should not be affected
	if data[0] == 'X' {
		t.Error("Serialized data should be a copy")
	}
}

func TestDataCopyOnDeserialize(t *testing.T) {
	// Test that deserialization makes a copy of the data
	ser := NewSerialisedCredential("password", []byte("password"))

	cred, _ := Deserialise(ser)
	pwCred := cred.(*PasswordCredential)

	// Modify original serialized data
	ser.Data[0] = 'X'

	// Deserialized credential should not be affected
	if pwCred.Password[0] == 'X' {
		t.Error("Deserialized data should be a copy")
	}
}
