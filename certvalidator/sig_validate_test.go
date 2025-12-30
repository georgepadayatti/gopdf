package certvalidator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestSignatureAlgorithmString(t *testing.T) {
	tests := []struct {
		algo     SignatureAlgorithm
		expected string
	}{
		{SigAlgoRSAPKCS1v15, "rsassa_pkcs1v15"},
		{SigAlgoRSAPSS, "rsassa_pss"},
		{SigAlgoDSA, "dsa"},
		{SigAlgoECDSA, "ecdsa"},
		{SigAlgoEd25519, "ed25519"},
		{SigAlgoEd448, "ed448"},
		{SigAlgoUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.algo.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, tt.algo.String())
			}
		})
	}
}

func TestGetSignatureAlgorithmFromOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected SignatureAlgorithm
	}{
		{"RSA with SHA1", OIDRSAWithSHA1, SigAlgoRSAPKCS1v15},
		{"RSA with SHA256", OIDRSAWithSHA256, SigAlgoRSAPKCS1v15},
		{"RSA with SHA384", OIDRSAWithSHA384, SigAlgoRSAPKCS1v15},
		{"RSA with SHA512", OIDRSAWithSHA512, SigAlgoRSAPKCS1v15},
		{"RSA PSS", OIDRSAPSS, SigAlgoRSAPSS},
		{"DSA with SHA1", OIDDSAWithSHA1, SigAlgoDSA},
		{"DSA with SHA256", OIDDSAWithSHA256, SigAlgoDSA},
		{"ECDSA with SHA1", OIDECDSAWithSHA1, SigAlgoECDSA},
		{"ECDSA with SHA256", OIDECDSAWithSHA256, SigAlgoECDSA},
		{"ECDSA with SHA384", OIDECDSAWithSHA384, SigAlgoECDSA},
		{"ECDSA with SHA512", OIDECDSAWithSHA512, SigAlgoECDSA},
		{"Ed25519", OIDEd25519, SigAlgoEd25519},
		{"Ed448", OIDEd448, SigAlgoEd448},
		{"Unknown", asn1.ObjectIdentifier{1, 2, 3}, SigAlgoUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetSignatureAlgorithmFromOID(tt.oid)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetHashAlgorithmFromOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected crypto.Hash
	}{
		{"SHA1", OIDSHA1, crypto.SHA1},
		{"SHA256", OIDSHA256, crypto.SHA256},
		{"SHA384", OIDSHA384, crypto.SHA384},
		{"SHA512", OIDSHA512, crypto.SHA512},
		{"Unknown", asn1.ObjectIdentifier{1, 2, 3}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHashAlgorithmFromOID(tt.oid)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetHashAlgorithmFromSigOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected crypto.Hash
	}{
		{"RSA with SHA1", OIDRSAWithSHA1, crypto.SHA1},
		{"RSA with SHA256", OIDRSAWithSHA256, crypto.SHA256},
		{"RSA with SHA384", OIDRSAWithSHA384, crypto.SHA384},
		{"RSA with SHA512", OIDRSAWithSHA512, crypto.SHA512},
		{"DSA with SHA1", OIDDSAWithSHA1, crypto.SHA1},
		{"DSA with SHA256", OIDDSAWithSHA256, crypto.SHA256},
		{"ECDSA with SHA1", OIDECDSAWithSHA1, crypto.SHA1},
		{"ECDSA with SHA256", OIDECDSAWithSHA256, crypto.SHA256},
		{"ECDSA with SHA384", OIDECDSAWithSHA384, crypto.SHA384},
		{"ECDSA with SHA512", OIDECDSAWithSHA512, crypto.SHA512},
		{"Unknown", asn1.ObjectIdentifier{1, 2, 3}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHashAlgorithmFromSigOID(tt.oid)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSignedDigestAlgorithm(t *testing.T) {
	t.Run("GetSignatureAlgo", func(t *testing.T) {
		sda := &SignedDigestAlgorithm{
			Algorithm: OIDRSAWithSHA256,
		}
		if sda.GetSignatureAlgo() != SigAlgoRSAPKCS1v15 {
			t.Errorf("expected RSA PKCS1v15, got %v", sda.GetSignatureAlgo())
		}
	})

	t.Run("GetHashAlgo", func(t *testing.T) {
		sda := &SignedDigestAlgorithm{
			Algorithm: OIDRSAWithSHA256,
		}
		if sda.GetHashAlgo() != crypto.SHA256 {
			t.Errorf("expected SHA256, got %v", sda.GetHashAlgo())
		}
	})
}

func TestNewDefaultSignatureValidator(t *testing.T) {
	v := NewDefaultSignatureValidator()
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestRSAPKCS1v15Signature(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("test data to sign")
	hash := sha256.Sum256(data)

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	t.Run("Valid signature", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDRSAWithSHA256}
		err := validator.ValidateSignature(signature, data, &privateKey.PublicKey, sigAlgo, nil)
		if err != nil {
			t.Errorf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("Invalid signature", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDRSAWithSHA256}
		badSignature := make([]byte, len(signature))
		copy(badSignature, signature)
		badSignature[0] ^= 0xFF // Corrupt the signature
		err := validator.ValidateSignature(badSignature, data, &privateKey.PublicKey, sigAlgo, nil)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("Prehashed data", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDRSAWithSHA256}
		context := &SignatureValidationContext{Prehashed: true}
		err := validator.ValidateSignature(signature, hash[:], &privateKey.PublicKey, sigAlgo, context)
		if err != nil {
			t.Errorf("expected valid signature with prehashed data, got error: %v", err)
		}
	})

	t.Run("Wrong key type", func(t *testing.T) {
		ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDRSAWithSHA256}
		err := validator.ValidateSignature(signature, data, &ecdsaKey.PublicKey, sigAlgo, nil)
		if err == nil {
			t.Error("expected error for wrong key type")
		}
	})
}

func TestECDSASignature(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("test data to sign")
	hash := sha256.Sum256(data)

	// Sign the data
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Encode as ASN.1
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}

	t.Run("Valid signature (ASN.1)", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDECDSAWithSHA256}
		err := validator.ValidateSignature(signature, data, &privateKey.PublicKey, sigAlgo, nil)
		if err != nil {
			t.Errorf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("Valid signature (raw format)", func(t *testing.T) {
		// Create raw signature (r || s)
		keySize := (privateKey.Curve.Params().BitSize + 7) / 8
		rawSig := make([]byte, 2*keySize)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(rawSig[keySize-len(rBytes):keySize], rBytes)
		copy(rawSig[2*keySize-len(sBytes):], sBytes)

		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDECDSAWithSHA256}
		err := validator.ValidateSignature(rawSig, data, &privateKey.PublicKey, sigAlgo, nil)
		if err != nil {
			t.Errorf("expected valid raw signature, got error: %v", err)
		}
	})

	t.Run("Invalid signature", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDECDSAWithSHA256}
		badSignature := make([]byte, len(signature))
		copy(badSignature, signature)
		badSignature[len(badSignature)-1] ^= 0xFF
		err := validator.ValidateSignature(badSignature, data, &privateKey.PublicKey, sigAlgo, nil)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})
}

func TestEd25519Signature(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("test data to sign")
	signature := ed25519.Sign(privateKey, data)

	t.Run("Valid signature", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDEd25519}
		err := validator.ValidateSignature(signature, data, publicKey, sigAlgo, nil)
		if err != nil {
			t.Errorf("expected valid signature, got error: %v", err)
		}
	})

	t.Run("Invalid signature", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDEd25519}
		badSignature := make([]byte, len(signature))
		copy(badSignature, signature)
		badSignature[0] ^= 0xFF
		err := validator.ValidateSignature(badSignature, data, publicKey, sigAlgo, nil)
		if err == nil {
			t.Error("expected error for invalid signature")
		}
	})

	t.Run("Wrong data", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDEd25519}
		err := validator.ValidateSignature(signature, []byte("different data"), publicKey, sigAlgo, nil)
		if err == nil {
			t.Error("expected error for wrong data")
		}
	})
}

func TestUnsupportedAlgorithm(t *testing.T) {
	t.Run("Ed448 not supported", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDEd448}
		err := validator.ValidateSignature(nil, nil, nil, sigAlgo, nil)
		if err == nil {
			t.Error("expected error for Ed448")
		}
	})

	t.Run("Unknown algorithm", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}
		err := validator.ValidateSignature(nil, nil, nil, sigAlgo, nil)
		if err == nil {
			t.Error("expected error for unknown algorithm")
		}
	})
}

func TestValidateSignatureRaw(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("test data")
	hash := sha256.Sum256(data)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])

	err = ValidateSignatureRaw(signature, data, &privateKey.PublicKey, OIDRSAWithSHA256, crypto.SHA256)
	if err != nil {
		t.Errorf("expected valid signature, got error: %v", err)
	}
}

func TestSignatureValidationContext(t *testing.T) {
	t.Run("Default context", func(t *testing.T) {
		ctx := &SignatureValidationContext{}
		if ctx.Prehashed {
			t.Error("expected prehashed to be false by default")
		}
		if ctx.ContextualMDAlgorithm != 0 {
			t.Error("expected contextual MD algorithm to be 0 by default")
		}
	})

	t.Run("Context with values", func(t *testing.T) {
		ctx := &SignatureValidationContext{
			ContextualMDAlgorithm: crypto.SHA384,
			Prehashed:             true,
		}
		if ctx.ContextualMDAlgorithm != crypto.SHA384 {
			t.Errorf("expected SHA384, got %v", ctx.ContextualMDAlgorithm)
		}
		if !ctx.Prehashed {
			t.Error("expected prehashed to be true")
		}
	})
}

func TestContextualHashAlgorithm(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("test data")
	hash := sha256.Sum256(data)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])

	// Use RSA encryption OID which doesn't specify hash
	validator := NewDefaultSignatureValidator()
	sigAlgo := &SignedDigestAlgorithm{Algorithm: OIDRSAEncryption}
	context := &SignatureValidationContext{ContextualMDAlgorithm: crypto.SHA256}

	err = validator.ValidateSignature(signature, data, &privateKey.PublicKey, sigAlgo, context)
	if err != nil {
		t.Errorf("expected valid signature with contextual hash, got error: %v", err)
	}
}

func TestRSAPSSSignature(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("test data to sign")
	hash := sha256.Sum256(data)

	// Use default salt length (20) to match verifier defaults
	opts := &rsa.PSSOptions{
		SaltLength: 20,
		Hash:       crypto.SHA256,
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], opts)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	t.Run("Valid PSS signature with default parameters", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		// Use no parameters - rely on defaults
		sigAlgo := &SignedDigestAlgorithm{
			Algorithm: OIDRSAPSS,
		}
		// Provide contextual hash since PSS OID doesn't specify hash
		context := &SignatureValidationContext{
			ContextualMDAlgorithm: crypto.SHA256,
		}
		err := validator.ValidateSignature(signature, data, &privateKey.PublicKey, sigAlgo, context)
		if err != nil {
			t.Errorf("expected valid PSS signature, got error: %v", err)
		}
	})

	t.Run("Invalid PSS signature", func(t *testing.T) {
		validator := NewDefaultSignatureValidator()
		sigAlgo := &SignedDigestAlgorithm{
			Algorithm: OIDRSAPSS,
		}
		context := &SignatureValidationContext{
			ContextualMDAlgorithm: crypto.SHA256,
		}
		badSignature := make([]byte, len(signature))
		copy(badSignature, signature)
		badSignature[0] ^= 0xFF
		err := validator.ValidateSignature(badSignature, data, &privateKey.PublicKey, sigAlgo, context)
		if err == nil {
			t.Error("expected error for invalid PSS signature")
		}
	})
}

func TestOIDConstants(t *testing.T) {
	// Test that OID constants are properly defined
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"OIDRSAEncryption", OIDRSAEncryption},
		{"OIDRSAWithSHA1", OIDRSAWithSHA1},
		{"OIDRSAWithSHA256", OIDRSAWithSHA256},
		{"OIDRSAWithSHA384", OIDRSAWithSHA384},
		{"OIDRSAWithSHA512", OIDRSAWithSHA512},
		{"OIDRSAPSS", OIDRSAPSS},
		{"OIDDSAWithSHA1", OIDDSAWithSHA1},
		{"OIDDSAWithSHA256", OIDDSAWithSHA256},
		{"OIDECPublicKey", OIDECPublicKey},
		{"OIDECDSAWithSHA1", OIDECDSAWithSHA1},
		{"OIDECDSAWithSHA256", OIDECDSAWithSHA256},
		{"OIDECDSAWithSHA384", OIDECDSAWithSHA384},
		{"OIDECDSAWithSHA512", OIDECDSAWithSHA512},
		{"OIDEd25519", OIDEd25519},
		{"OIDEd448", OIDEd448},
		{"OIDSHA1", OIDSHA1},
		{"OIDSHA256", OIDSHA256},
		{"OIDSHA384", OIDSHA384},
		{"OIDSHA512", OIDSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.oid) == 0 {
				t.Errorf("%s should not be empty", tt.name)
			}
		})
	}
}

func TestErrorTypes(t *testing.T) {
	t.Run("ErrAlgorithmNotSupported", func(t *testing.T) {
		if ErrAlgorithmNotSupported == nil {
			t.Error("ErrAlgorithmNotSupported should not be nil")
		}
	})

	t.Run("ErrDSAParametersUnavailable", func(t *testing.T) {
		if ErrDSAParametersUnavailable == nil {
			t.Error("ErrDSAParametersUnavailable should not be nil")
		}
	})

	t.Run("ErrPSSParameterMismatch", func(t *testing.T) {
		if ErrPSSParameterMismatch == nil {
			t.Error("ErrPSSParameterMismatch should not be nil")
		}
	})

	t.Run("ErrInvalidSignature", func(t *testing.T) {
		if ErrInvalidSignature == nil {
			t.Error("ErrInvalidSignature should not be nil")
		}
	})
}
