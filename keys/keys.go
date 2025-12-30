// Package keys provides utilities for loading certificates and private keys
// from PEM and DER encoded files.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Common errors
var (
	ErrNoCertFound       = errors.New("no certificate found in data")
	ErrNoKeyFound        = errors.New("no private key found in data")
	ErrUnknownKeyType    = errors.New("unknown private key type")
	ErrInvalidPEMBlock   = errors.New("invalid PEM block")
	ErrDecryptionFailed  = errors.New("failed to decrypt private key")
	ErrMultipleCerts     = errors.New("expected exactly one certificate")
	ErrUnsupportedFormat = errors.New("unsupported key format")
)

// PrivateKey represents a private key that can be used for signing.
type PrivateKey interface {
	crypto.Signer
}

// LoadCertFromPemDer loads a single certificate from a PEM or DER encoded file.
func LoadCertFromPemDer(filename string) (*x509.Certificate, error) {
	certs, err := LoadCertsFromPemDer(filename)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("%w: found %d certificates in %s", ErrMultipleCerts, len(certs), filename)
	}
	return certs[0], nil
}

// LoadCertsFromPemDer loads certificates from a PEM or DER encoded file.
func LoadCertsFromPemDer(filename string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}
	return LoadCertsFromPemDerData(data)
}

// LoadCertsFromPemDerData loads certificates from PEM or DER encoded data.
func LoadCertsFromPemDerData(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Try to detect if it's PEM encoded
	if isPEM(data) {
		// Parse all PEM blocks
		rest := data
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}

			// Only process CERTIFICATE blocks
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse certificate: %w", err)
				}
				certs = append(certs, cert)
			}
		}
	} else {
		// Try DER format - could be a single cert or a PKCS#7 bundle
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			// Try parsing as multiple certificates
			parsedCerts, parseErr := x509.ParseCertificates(data)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
			}
			certs = parsedCerts
		} else {
			certs = []*x509.Certificate{cert}
		}
	}

	if len(certs) == 0 {
		return nil, ErrNoCertFound
	}

	return certs, nil
}

// LoadCertsFromPemDerFiles loads certificates from multiple files.
func LoadCertsFromPemDerFiles(filenames []string) ([]*x509.Certificate, error) {
	var allCerts []*x509.Certificate
	for _, filename := range filenames {
		certs, err := LoadCertsFromPemDer(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to load certs from %s: %w", filename, err)
		}
		allCerts = append(allCerts, certs...)
	}
	return allCerts, nil
}

// LoadPrivateKeyFromPemDer loads a private key from a PEM or DER encoded file.
func LoadPrivateKeyFromPemDer(filename string, passphrase []byte) (PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}
	return LoadPrivateKeyFromPemDerData(data, passphrase)
}

// LoadPrivateKeyFromPemDerData loads a private key from PEM or DER encoded data.
func LoadPrivateKeyFromPemDerData(data []byte, passphrase []byte) (PrivateKey, error) {
	if isPEM(data) {
		return loadPrivateKeyFromPEM(data, passphrase)
	}
	return loadPrivateKeyFromDER(data)
}

// loadPrivateKeyFromPEM parses a PEM encoded private key.
func loadPrivateKeyFromPEM(data []byte, passphrase []byte) (PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEMBlock
	}

	var keyBytes []byte
	var err error

	// Check if the key is encrypted
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		if passphrase == nil {
			return nil, fmt.Errorf("private key is encrypted but no passphrase provided")
		}
		keyBytes, err = x509.DecryptPEMBlock(block, passphrase) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}
	} else {
		keyBytes = block.Bytes
	}

	return parsePrivateKeyByType(block.Type, keyBytes)
}

// loadPrivateKeyFromDER parses a DER encoded private key.
func loadPrivateKeyFromDER(data []byte) (PrivateKey, error) {
	// Try PKCS#8 first
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return toPrivateKey(key)
	}

	// Try PKCS#1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}

	// Try EC
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}

	return nil, ErrNoKeyFound
}

// parsePrivateKeyByType parses a private key based on the PEM block type.
func parsePrivateKeyByType(blockType string, keyBytes []byte) (PrivateKey, error) {
	switch blockType {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBytes)
	case "PRIVATE KEY":
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		return toPrivateKey(key)
	case "ENCRYPTED PRIVATE KEY":
		// For PKCS#8 encrypted keys, the decryption should have already happened
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		return toPrivateKey(key)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyType, blockType)
	}
}

// toPrivateKey converts a parsed key interface to our PrivateKey type.
func toPrivateKey(key interface{}) (PrivateKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnknownKeyType, key)
	}
}

// isPEM checks if the data appears to be PEM encoded.
func isPEM(data []byte) bool {
	return len(data) > 10 && string(data[:5]) == "-----"
}

// KeyInfo contains information about a private key.
type KeyInfo struct {
	// Algorithm is the key algorithm (RSA, ECDSA, Ed25519)
	Algorithm string

	// BitSize is the key size in bits (for RSA)
	BitSize int

	// Curve is the elliptic curve name (for ECDSA)
	Curve string
}

// GetKeyInfo returns information about a private key.
func GetKeyInfo(key PrivateKey) KeyInfo {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return KeyInfo{
			Algorithm: "RSA",
			BitSize:   k.N.BitLen(),
		}
	case *ecdsa.PrivateKey:
		return KeyInfo{
			Algorithm: "ECDSA",
			Curve:     k.Curve.Params().Name,
		}
	case ed25519.PrivateKey:
		return KeyInfo{
			Algorithm: "Ed25519",
		}
	default:
		return KeyInfo{Algorithm: "Unknown"}
	}
}

// CertificateChain represents a chain of certificates.
type CertificateChain struct {
	// EndEntity is the end-entity (leaf) certificate.
	EndEntity *x509.Certificate

	// Intermediates are the intermediate certificates.
	Intermediates []*x509.Certificate

	// Root is the root certificate (if present).
	Root *x509.Certificate
}

// LoadCertificateChain loads a certificate chain from files.
// The first file should contain the end-entity certificate.
func LoadCertificateChain(certFiles []string) (*CertificateChain, error) {
	if len(certFiles) == 0 {
		return nil, errors.New("no certificate files provided")
	}

	var allCerts []*x509.Certificate
	for _, file := range certFiles {
		certs, err := LoadCertsFromPemDer(file)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert from %s: %w", file, err)
		}
		allCerts = append(allCerts, certs...)
	}

	if len(allCerts) == 0 {
		return nil, ErrNoCertFound
	}

	chain := &CertificateChain{
		EndEntity: allCerts[0],
	}

	if len(allCerts) > 1 {
		chain.Intermediates = allCerts[1:]

		// Check if the last cert is a root (self-signed)
		lastCert := allCerts[len(allCerts)-1]
		if isSelfSigned(lastCert) {
			chain.Root = lastCert
			chain.Intermediates = allCerts[1 : len(allCerts)-1]
		}
	}

	return chain, nil
}

// isSelfSigned checks if a certificate is self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// LoadCertAndKeyFromPemDer loads a certificate and private key from files.
func LoadCertAndKeyFromPemDer(certFile, keyFile string, passphrase []byte) (*x509.Certificate, PrivateKey, error) {
	cert, err := LoadCertFromPemDer(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	key, err := LoadPrivateKeyFromPemDer(keyFile, passphrase)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return cert, key, nil
}

// PKCS12Credential holds a certificate and key loaded from a PKCS#12 file.
type PKCS12Credential struct {
	Certificate *x509.Certificate
	PrivateKey  PrivateKey
	CACerts     []*x509.Certificate
}

// Note: PKCS#12 support would require a third-party library like
// software.sslmate.com/src/go-pkcs12 which is not in the standard library.
// For now, we'll leave this as a placeholder.
