# PDF Signing Guide

This guide covers all aspects of PDF digital signing with gopdf, including ETSI-compliant signatures, certificate handling, and various signing scenarios.

Disclaimer: This is a fun experiment; use at your peril. It is not intended for production use.

## Table of Contents

- [Overview](#overview)
- [Signature Types](#signature-types)
- [Basic Signing](#basic-signing)
- [ETSI Compliant Signing](#etsi-compliant-signing)
- [Cloud Signing with CSC API](#cloud-signing-with-csc-api)
- [Hardware Token Signing (PKCS#11)](#hardware-token-signing-pkcs11)
- [Certification Signatures](#certification-signatures)
- [Signature Verification](#signature-verification)

## Overview

The gopdf library supports multiple signature formats and complies with international standards:

| Standard | Description |
|----------|-------------|
| PAdES | PDF Advanced Electronic Signatures (ETSI TS 103 171) |
| CAdES | CMS Advanced Electronic Signatures (ETSI TS 103 182) |
| RFC 5652 | Cryptographic Message Syntax |
| ISO 32000-2 | PDF 2.0 Specification |

## Signature Types

### PAdES Baseline Signatures

```go
// Standard PDF signature (PAdES-B)
metadata := signers.NewSignatureMetadata("Signature1")
metadata.SubFilter = "adbe.pkcs7.detached"
```

### CAdES Detached Signatures

```go
// ETSI CAdES signature
metadata := signers.NewSignatureMetadata("Signature1")
metadata.SubFilter = "ETSI.CAdES.detached"
```

## Basic Signing

### Loading Certificates

**From PEM Files:**

```go
import (
    "crypto/x509"
    "encoding/pem"
    "os"
)

func loadCertPEM(path string) (*x509.Certificate, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(data)
    return x509.ParseCertificate(block.Bytes)
}

func loadKeyPEM(path string) (crypto.Signer, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(data)

    // Try PKCS#8 first
    if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
        return key.(crypto.Signer), nil
    }

    // Try PKCS#1 RSA
    if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
        return key, nil
    }

    // Try EC key
    return x509.ParseECPrivateKey(block.Bytes)
}
```

**From PKCS#12:**

```go
import "software.sslmate.com/src/go-pkcs12"

func loadP12(path, password string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, nil, nil, err
    }

    key, cert, caCerts, err := pkcs12.DecodeChain(data, password)
    if err != nil {
        return nil, nil, nil, err
    }

    return cert, key.(crypto.Signer), caCerts, nil
}
```

### Creating a Simple Signer

```go
import (
    "github.com/georgepadayatti/gopdf/sign/cms"
    "github.com/georgepadayatti/gopdf/sign/signers"
)

// Create signer with certificate and key
signer := signers.NewSimpleSigner(cert, privateKey, cms.SHA256WithRSA)

// Include certificate chain for validation
signer.SetCertificateChain(caCerts)
```

### Signing a PDF

```go
// Create signature metadata
metadata := signers.NewSignatureMetadata("Signature1")
metadata.Reason = "Document approval"
metadata.Location = "Berlin, Germany"
metadata.Name = cert.Subject.CommonName
metadata.ContactInfo = "contact@example.com"

// Sign PDF bytes
pdfData, _ := os.ReadFile("document.pdf")
signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, nil)
if err != nil {
    log.Fatalf("Signing failed: %v", err)
}

// Save signed PDF
os.WriteFile("document_signed.pdf", signedData, 0644)
```

### Using the Quick Sign API

```go
// Fluent API for simple signing
qs := signers.NewQuickSign(signer, "Signature1").
    WithReason("Document approval").
    WithLocation("Berlin, Germany")

signedData, err := qs.Sign(pdfData)
```

## ETSI Compliant Signing

### PAdES Baseline B (B-Level)

```go
// Create enhanced metadata for ETSI compliance
metadata := signers.NewEnhancedSignatureMetadata("ETSISignature").
    WithReason("Contract approval").
    WithLocation("Brussels, Belgium").
    WithName(cert.Subject.CommonName).
    WithAdES()  // Enable ETSI CAdES.detached

// Sign with timestamp for PAdES-T
opts := signers.DefaultSignPdfOptions()
opts.Timestamper = timestamps.NewHTTPTimestamper("https://freetsa.org/tsr")

signedData, err := signers.SignPdfBytes(pdfData, metadata.SignatureMetadata, signer, opts)
```

### PAdES Baseline T (T-Level with Timestamp)

```go
import "github.com/georgepadayatti/gopdf/sign/timestamps"

// Create HTTP timestamper
timestamper := timestamps.NewHTTPTimestamper("https://tsa.example.com")

// Optional: Set credentials for authenticated TSA
timestamper.SetCredentials("username", "password")

// Sign with timestamp
opts := signers.DefaultSignPdfOptions()
opts.Timestamper = timestamper

signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, opts)
```

### PAdES Baseline LT (LT-Level with LTV Data)

```go
import "github.com/georgepadayatti/gopdf/sign/dss"

// Create DSS (Document Security Store) settings
dssSettings := signers.NewDSSContentSettings()
dssSettings.PlacementPreference = signers.DSSPlacementSeparateRevision
dssSettings.IncludeVRI = true

// Add certificates
dssSettings.Certificates = append(dssSettings.Certificates, cert)
dssSettings.Certificates = append(dssSettings.Certificates, caCerts...)

// Add OCSP responses (if available)
// dssSettings.OCSPs = append(dssSettings.OCSPs, ocspResponse)

// Add CRLs (if available)
// dssSettings.CRLs = append(dssSettings.CRLs, crlData)
```

### Adding Commitment Types

```go
// Commitment type OIDs
var (
    OIDProofOfOrigin   = []int{1, 2, 840, 113549, 1, 9, 16, 6, 1}
    OIDProofOfReceipt  = []int{1, 2, 840, 113549, 1, 9, 16, 6, 2}
    OIDProofOfApproval = []int{1, 2, 840, 113549, 1, 9, 16, 6, 4}
)

// Set commitment type in enhanced metadata
metadata := signers.NewEnhancedSignatureMetadata("Signature1").
    WithAdES()
metadata.CommitmentType = OIDProofOfApproval
```

## Cloud Signing with CSC API

The Cloud Signature Consortium (CSC) API enables remote signing with cloud-based keys.

### Configuration

```go
// CSC service configuration
type CSCConfig struct {
    ServiceURL   string  // Base URL of CSC service
    CredentialID string  // Signing credential ID
    OAuthURL     string  // OAuth token endpoint
    ClientID     string  // OAuth client ID
    ClientSecret string  // OAuth client secret
    PIN          string  // User PIN for credential authorization
}
```

### Complete CSC Signing Flow

```go
import (
    "context"
    "net/http"

    "github.com/georgepadayatti/gopdf/sign/signers"
)

func signWithCSC(ctx context.Context, pdfData []byte, config *CSCConfig) ([]byte, error) {
    httpClient := &http.Client{}

    // Step 1: Create CSC session
    sessionInfo := signers.NewCSCServiceSessionInfo(config.ServiceURL, config.CredentialID)
    sessionInfo.WithOAuthToken(config.AccessToken)

    // Step 2: Fetch certificates from CSC service
    credInfo, err := signers.FetchCertsInCSCCredential(ctx, httpClient, sessionInfo)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch credentials: %w", err)
    }

    // Step 3: Create authorization with pre-fetched SAD
    authInfo := &signers.CSCAuthorizationInfo{
        SAD:       sadToken,  // Signing Authorization Data
        ExpiresAt: time.Now().Add(5 * time.Minute),
    }

    authManager := signers.NewPrefetchedSADAuthorizationManager(
        sessionInfo, credInfo, authInfo,
    )

    // Step 4: Create CSC signer
    cscSigner := signers.NewCSCSigner(authManager, httpClient)
    cmsSigner := signers.NewCMSSignerAdapter(cscSigner, "sha256")

    // Step 5: Sign PDF
    metadata := signers.NewSignatureMetadata("CSCSignature")
    metadata.Reason = "Remote signing with CSC"
    metadata.Name = credInfo.SigningCert.Subject.CommonName

    return signers.SignPdfBytes(pdfData, metadata, cmsSigner, nil)
}
```

### Environment Variables for CSC

```bash
export CSC_SERVICE_URL="https://csc-service.example.com"
export CSC_CREDENTIAL_ID="your-credential-id"
export CSC_OAUTH_URL="https://csc-service.example.com/oauth/token"
export CSC_CLIENT_ID="your-client-id"
export CSC_CLIENT_SECRET="your-client-secret"
export CSC_PIN="your-pin"
export TSA_URL="https://freetsa.org/tsr"  # Optional timestamp server
```

## Hardware Token Signing (PKCS#11)

### PKCS#11 Configuration

```go
import "github.com/georgepadayatti/gopdf/sign/signers"

// PKCS#11 token configuration
pkcs11Config := &signers.PKCS11Config{
    Module:     "/usr/lib/softhsm/libsofthsm2.so",  // PKCS#11 library path
    SlotNumber: 0,                                   // Token slot
    PIN:        "1234",                              // User PIN
    KeyLabel:   "signing-key",                       // Private key label
}

// Create PKCS#11 signer
pkcs11Signer, err := signers.NewPKCS11Signer(pkcs11Config)
if err != nil {
    log.Fatalf("Failed to create PKCS#11 signer: %v", err)
}
defer pkcs11Signer.Close()

// Sign PDF
signedData, err := signers.SignPdfBytes(pdfData, metadata, pkcs11Signer, nil)
```

### Supported PKCS#11 Mechanisms

| Mechanism | Algorithm |
|-----------|-----------|
| CKM_RSA_PKCS | RSA PKCS#1 v1.5 |
| CKM_RSA_PKCS_PSS | RSA-PSS |
| CKM_ECDSA | ECDSA |
| CKM_DSA | DSA |

## Certification Signatures

Certification signatures define what modifications are allowed after signing.

### Certification Levels

```go
const (
    // No changes allowed after signing
    SigCertNoChanges SigCertificationLevel = 1

    // Form filling allowed after signing
    SigCertFormFilling SigCertificationLevel = 2

    // Annotations and form filling allowed
    SigCertAnnotations SigCertificationLevel = 3
)
```

### Creating a Certification Signature

```go
// Create certification signature that only allows form filling
metadata := signers.NewEnhancedSignatureMetadata("CertificationSig").
    WithReason("Document certification").
    AsCertification(signers.SigCertFormFilling)
```

## Signature Verification

### Verifying Signatures

```go
import (
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/sign/cms"
)

func verifySignatures(pdfData []byte, trustedCAs []*x509.Certificate) error {
    // Parse PDF
    pdfReader, err := reader.NewPdfFileReaderFromBytes(pdfData)
    if err != nil {
        return err
    }

    // Get embedded signatures
    signatures, err := pdfReader.GetEmbeddedSignatures()
    if err != nil {
        return err
    }

    for _, sig := range signatures {
        // Get signature contents and signed data
        signatureBytes := trimTrailingZeros(sig.Contents)
        signedData := sig.GetSignedData()

        // Verify CMS signature
        if err := cms.VerifyCMSSignature(signatureBytes, signedData); err != nil {
            return fmt.Errorf("signature integrity check failed: %w", err)
        }

        // Get signer certificate
        certs, _ := cms.GetSignerCertificates(signatureBytes)
        if len(certs) == 0 {
            return fmt.Errorf("no signer certificate found")
        }

        // Verify certificate chain
        roots := x509.NewCertPool()
        for _, ca := range trustedCAs {
            roots.AddCert(ca)
        }

        opts := x509.VerifyOptions{
            Roots:     roots,
            KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
        }

        if _, err := certs[0].Verify(opts); err != nil {
            return fmt.Errorf("certificate verification failed: %w", err)
        }

        fmt.Printf("Signature by %s is valid\n", certs[0].Subject.CommonName)
    }

    return nil
}
```

### Signature Metadata Extraction

```go
// Extract signature details
for _, sig := range signatures {
    fmt.Printf("Field: %s\n", sig.GetFieldName())
    fmt.Printf("Signer: %s\n", sig.GetSignerName())
    fmt.Printf("Reason: %s\n", sig.GetReason())
    fmt.Printf("Location: %s\n", sig.GetLocation())
    fmt.Printf("Signing Time: %s\n", sig.GetSigningTime())
}
```

## External Signing

For custom signing implementations (e.g., custom HSMs, remote services):

```go
// Create external signer with custom signing function
externalSigner := signers.NewExternalSigner(
    cert,
    func(digest []byte) ([]byte, error) {
        // Custom signing logic
        // - Send digest to external service
        // - Receive signature bytes
        return myCustomSign(digest)
    },
    cms.SHA256WithRSA,
)

// Use like any other signer
signedData, err := signers.SignPdfBytes(pdfData, metadata, externalSigner, nil)
```

## Best Practices

1. **Always include certificate chain**: Include intermediate CA certificates for proper validation
2. **Use timestamps**: Add RFC 3161 timestamps for long-term validity
3. **Protect private keys**: Use PKCS#11 or CSC for production environments
4. **Validate before signing**: Use pre-sign validation to catch certificate issues early
5. **Handle errors gracefully**: Always check for errors at each step
6. **Use appropriate signature format**: Choose PAdES or CAdES based on requirements

## Error Handling

```go
signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, opts)
if err != nil {
    var signingErr *signers.SigningError
    if errors.As(err, &signingErr) {
        log.Printf("Signing error: %s (cause: %v)", signingErr.Message, signingErr.Cause)
    }
    return nil, err
}
```
