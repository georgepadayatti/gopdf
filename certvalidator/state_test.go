package certvalidator

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
)

func TestConsList(t *testing.T) {
	t.Run("NewConsList", func(t *testing.T) {
		list := NewConsList("a")
		if list.Head != "a" {
			t.Errorf("expected head 'a', got %v", list.Head)
		}
		if list.Tail != nil {
			t.Error("expected nil tail")
		}
	})

	t.Run("Prepend", func(t *testing.T) {
		list := NewConsList("b")
		list = list.Prepend("a")
		if list.Head != "a" {
			t.Errorf("expected head 'a', got %v", list.Head)
		}
		if list.Tail.Head != "b" {
			t.Errorf("expected tail head 'b', got %v", list.Tail.Head)
		}
	})

	t.Run("IsEmpty", func(t *testing.T) {
		var list *ConsList[string]
		if !list.IsEmpty() {
			t.Error("expected empty list")
		}
		list = NewConsList("a")
		if list.IsEmpty() {
			t.Error("expected non-empty list")
		}
	})

	t.Run("Len", func(t *testing.T) {
		var list *ConsList[int]
		if list.Len() != 0 {
			t.Errorf("expected length 0, got %d", list.Len())
		}
		list = NewConsList(1)
		if list.Len() != 1 {
			t.Errorf("expected length 1, got %d", list.Len())
		}
		list = list.Prepend(2)
		list = list.Prepend(3)
		if list.Len() != 3 {
			t.Errorf("expected length 3, got %d", list.Len())
		}
	})

	t.Run("ToSlice", func(t *testing.T) {
		var list *ConsList[string]
		slice := list.ToSlice()
		if slice != nil {
			t.Errorf("expected nil slice, got %v", slice)
		}

		list = NewConsList("c")
		list = list.Prepend("b")
		list = list.Prepend("a")
		slice = list.ToSlice()
		if len(slice) != 3 {
			t.Errorf("expected slice length 3, got %d", len(slice))
		}
		if slice[0] != "a" || slice[1] != "b" || slice[2] != "c" {
			t.Errorf("unexpected slice contents: %v", slice)
		}
	})
}

func createTestCert(subject string, serialNumber int64) *x509.Certificate {
	return &x509.Certificate{
		Subject:      pkix.Name{CommonName: subject},
		SerialNumber: big.NewInt(serialNumber),
		Raw:          []byte(subject), // Simplified for testing
	}
}

func TestValidationPath(t *testing.T) {
	trustAnchor := createTestCert("Root CA", 1)
	intermediate := createTestCert("Intermediate CA", 2)
	endEntity := createTestCert("End Entity", 3)

	t.Run("NewValidationPath", func(t *testing.T) {
		path := NewValidationPath(trustAnchor)
		if path.TrustAnchor != trustAnchor {
			t.Error("trust anchor not set correctly")
		}
		if len(path.Intermediates) != 0 {
			t.Error("expected empty intermediates")
		}
		if path.EECert != nil {
			t.Error("expected nil EE cert")
		}
	})

	t.Run("AddIntermediate", func(t *testing.T) {
		path := NewValidationPath(trustAnchor)
		path.AddIntermediate(intermediate)
		if len(path.Intermediates) != 1 {
			t.Errorf("expected 1 intermediate, got %d", len(path.Intermediates))
		}
		if path.Intermediates[0] != intermediate {
			t.Error("intermediate not added correctly")
		}
	})

	t.Run("SetEECert", func(t *testing.T) {
		path := NewValidationPath(trustAnchor)
		path.SetEECert(endEntity)
		if path.EECert != endEntity {
			t.Error("EE cert not set correctly")
		}
	})

	t.Run("PKIXLen", func(t *testing.T) {
		path := NewValidationPath(trustAnchor)
		if path.PKIXLen() != 0 {
			t.Errorf("expected length 0, got %d", path.PKIXLen())
		}

		path.AddIntermediate(intermediate)
		if path.PKIXLen() != 1 {
			t.Errorf("expected length 1, got %d", path.PKIXLen())
		}

		path.SetEECert(endEntity)
		if path.PKIXLen() != 2 {
			t.Errorf("expected length 2, got %d", path.PKIXLen())
		}
	})

	t.Run("GetEECertSafe", func(t *testing.T) {
		path := NewValidationPath(trustAnchor)
		if path.GetEECertSafe() != nil {
			t.Error("expected nil EE cert")
		}
		path.SetEECert(endEntity)
		if path.GetEECertSafe() != endEntity {
			t.Error("expected EE cert to be returned")
		}
	})

	t.Run("AllCerts", func(t *testing.T) {
		path := NewValidationPath(trustAnchor)
		path.AddIntermediate(intermediate)
		path.SetEECert(endEntity)

		certs := path.AllCerts()
		if len(certs) != 3 {
			t.Errorf("expected 3 certs, got %d", len(certs))
		}
		if certs[0] != trustAnchor {
			t.Error("first cert should be trust anchor")
		}
		if certs[1] != intermediate {
			t.Error("second cert should be intermediate")
		}
		if certs[2] != endEntity {
			t.Error("third cert should be end entity")
		}
	})
}

func TestCertSHA256(t *testing.T) {
	cert := createTestCert("Test Cert", 1)
	hash1 := CertSHA256(cert)
	hash2 := CertSHA256(cert)

	if hash1 != hash2 {
		t.Error("same cert should produce same hash")
	}

	cert2 := createTestCert("Different Cert", 2)
	hash3 := CertSHA256(cert2)
	if hash1 == hash3 {
		t.Error("different certs should produce different hashes")
	}
}

func TestValProcState(t *testing.T) {
	trustAnchor := createTestCert("Root CA", 1)
	intermediate := createTestCert("Intermediate CA", 2)
	endEntity := createTestCert("End Entity", 3)

	path := NewValidationPath(trustAnchor)
	path.AddIntermediate(intermediate)
	path.SetEECert(endEntity)

	t.Run("NewValProcState", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, err := NewValProcState(pathStack)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if state.Index != 0 {
			t.Errorf("expected index 0, got %d", state.Index)
		}
		if state.IsSideValidation {
			t.Error("expected not side validation")
		}
	})

	t.Run("NewValProcState empty stack", func(t *testing.T) {
		_, err := NewValProcState(nil)
		if err == nil {
			t.Error("expected error for empty stack")
		}
	})

	t.Run("NewValProcState with options", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, err := NewValProcState(pathStack,
			WithEENameOverride("CRL issuer"),
			WithInitIndex(1),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if state.EENameOverride != "CRL issuer" {
			t.Errorf("expected EE name override 'CRL issuer', got %s", state.EENameOverride)
		}
		if state.Index != 1 {
			t.Errorf("expected index 1, got %d", state.Index)
		}
	})

	t.Run("PathLen", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, _ := NewValProcState(pathStack)
		if state.PathLen() != 2 {
			t.Errorf("expected path length 2, got %d", state.PathLen())
		}
	})

	t.Run("IsEECert", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, _ := NewValProcState(pathStack)
		if state.IsEECert() {
			t.Error("index 0 should not be EE cert")
		}
		state.Index = 1
		if state.IsEECert() {
			t.Error("index 1 should not be EE cert")
		}
		state.Index = 2
		if !state.IsEECert() {
			t.Error("index 2 should be EE cert")
		}
	})

	t.Run("Advance and Reset", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, _ := NewValProcState(pathStack)
		state.Advance()
		if state.Index != 1 {
			t.Errorf("expected index 1 after advance, got %d", state.Index)
		}
		state.Advance()
		if state.Index != 2 {
			t.Errorf("expected index 2 after advance, got %d", state.Index)
		}
		state.Reset()
		if state.Index != 0 {
			t.Errorf("expected index 0 after reset, got %d", state.Index)
		}
	})

	t.Run("DescribeCert", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, _ := NewValProcState(pathStack)

		// Trust anchor - with neverDef=true to get plain "trust anchor"
		desc := state.DescribeCert(false, true)
		if desc != "trust anchor" {
			t.Errorf("expected 'trust anchor', got %s", desc)
		}

		// Intermediate
		state.Index = 1
		desc = state.DescribeCert(true, false)
		if desc != "the intermediate certificate 1" {
			t.Errorf("expected 'the intermediate certificate 1', got %s", desc)
		}

		// End entity
		state.Index = 2
		desc = state.DescribeCert(false, false)
		if desc != "the end-entity certificate" {
			t.Errorf("expected 'the end-entity certificate', got %s", desc)
		}

		// With EE name override
		state.EENameOverride = "CRL issuer"
		desc = state.DescribeCert(false, false)
		if desc != "the CRL issuer" {
			t.Errorf("expected 'the CRL issuer', got %s", desc)
		}

		// Without prefix
		desc = state.DescribeCert(false, true)
		if desc != "CRL issuer" {
			t.Errorf("expected 'CRL issuer', got %s", desc)
		}
	})

	t.Run("CheckPathVerifRecursion", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, _ := NewValProcState(pathStack)

		// Should find existing EE cert
		result := state.CheckPathVerifRecursion(endEntity)
		if result == nil {
			t.Error("expected to find path with EE cert")
		}

		// Should not find different cert
		differentCert := createTestCert("Different", 100)
		result = state.CheckPathVerifRecursion(differentCert)
		if result != nil {
			t.Error("should not find path with different cert")
		}

		// Nil cert should return nil
		result = state.CheckPathVerifRecursion(nil)
		if result != nil {
			t.Error("nil cert should return nil")
		}
	})

	t.Run("GetCurrentPath", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, _ := NewValProcState(pathStack)
		currentPath := state.GetCurrentPath()
		if currentPath != path {
			t.Error("expected current path to be the initial path")
		}
	})

	t.Run("PushPath and PopPath", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, _ := NewValProcState(pathStack)

		// Create a new path for side validation
		sidePath := NewValidationPath(trustAnchor)
		sidePath.SetEECert(createTestCert("Side EE", 10))

		state.PushPath(sidePath)
		if !state.IsSideValidation {
			t.Error("expected side validation after push")
		}
		if state.GetCurrentPath() != sidePath {
			t.Error("current path should be side path after push")
		}

		popped := state.PopPath()
		if popped != sidePath {
			t.Error("popped path should be side path")
		}
		if state.GetCurrentPath() != path {
			t.Error("current path should be original path after pop")
		}
	})

	t.Run("Clone", func(t *testing.T) {
		pathStack := NewConsList(path)
		state, _ := NewValProcState(pathStack, WithEENameOverride("test"))
		state.Index = 1

		cloned := state.Clone()
		if cloned.Index != state.Index {
			t.Error("cloned state should have same index")
		}
		if cloned.EENameOverride != state.EENameOverride {
			t.Error("cloned state should have same EE name override")
		}

		// Modifying clone should not affect original
		cloned.Index = 99
		if state.Index == 99 {
			t.Error("modifying clone should not affect original")
		}
	})

	t.Run("SideValidation with stacked paths", func(t *testing.T) {
		path2 := NewValidationPath(trustAnchor)
		path2.SetEECert(createTestCert("Second EE", 20))

		pathStack := NewConsList(path)
		pathStack = pathStack.Prepend(path2)

		state, _ := NewValProcState(pathStack)
		if !state.IsSideValidation {
			t.Error("expected side validation with stacked paths")
		}
	})
}
