# gopdf

A Go library for PDF digital signatures with comprehensive support for ETSI standards, visual signatures, timestamps, and cloud-based signing.

Disclaimer: This is a fun experiment; use at your peril. It is not intended for production use.

## Features

- **Digital Signatures**: PAdES (PDF Advanced Electronic Signatures) and CAdES (CMS Advanced Electronic Signatures)
- **ETSI Compliance**: Full support for ETSI TS 103 171 (PAdES) and ETSI TS 103 182 standards
- **Multiple Signing Sources**:
  - Local certificates (PEM, PKCS#12)
  - Hardware tokens via PKCS#11 (HSM, smart cards)
  - Cloud Signature Consortium (CSC) API for remote signing
- **RFC 3161 Timestamps**: Document and signature timestamps from trusted TSA servers
- **Visual Signatures**: Customizable signature appearances with images, text, and watermarks
- **Long-Term Validation (LTV)**: DSS (Document Security Store) support for archival signatures
- **Signature Verification**: Complete validation of signatures, certificates, and revocation status

## Installation

```bash
go get github.com/georgepadayatti/gopdf
```

## Quick Start

### Sign a PDF with a Local Certificate

```go
package main

import (
    "os"

    "github.com/georgepadayatti/gopdf/sign/cms"
    "github.com/georgepadayatti/gopdf/sign/signers"
    "software.sslmate.com/src/go-pkcs12"
)

func main() {
    // Load certificate and key from PKCS#12
    p12Data, _ := os.ReadFile("signer.p12")
    key, cert, chain, _ := pkcs12.DecodeChain(p12Data, "password")

    // Create signer
    signer := signers.NewSimpleSigner(cert, key.(crypto.Signer), cms.SHA256WithRSA)
    signer.SetCertificateChain(chain)

    // Create signature metadata
    metadata := signers.NewSignatureMetadata("Signature1")
    metadata.Reason = "Document approval"
    metadata.Location = "Berlin, Germany"
    metadata.Name = cert.Subject.CommonName

    // Sign PDF
    pdfData, _ := os.ReadFile("document.pdf")
    signedData, _ := signers.SignPdfBytes(pdfData, metadata, signer, nil)

    os.WriteFile("document_signed.pdf", signedData, 0644)
}
```

### Add a Visible Signature with Image

```go
package main

import (
    "os"

    "github.com/georgepadayatti/gopdf/pdf/generic"
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/sign/cms"
    "github.com/georgepadayatti/gopdf/sign/signers"
    "github.com/georgepadayatti/gopdf/stamp"
)

func main() {
    // ... load certificate and create signer ...

    // Create PDF signer with visible signature
    pdfSigner := signers.NewPdfSigner(signer, metadata)

    // Define signature rectangle (x1, y1, x2, y2 in points)
    rect := &generic.Rectangle{LLX: 50, LLY: 50, URX: 250, URY: 120}
    pdfSigner.SetSignatureAppearance(0, rect) // Page 0 (first page)

    // Create visual signature configuration
    config := stamp.DefaultVisualSignatureConfig()
    config.SignerName = "John Doe"
    config.Reason = "Document approval"
    config.Location = "Berlin, Germany"

    // Optionally add an image
    imageData, _ := os.ReadFile("signature.png")
    config.Image = imageData
    config.ImagePosition = stamp.ImageTextPositionLeft
    config.ImageRatio = 0.4

    // Sign PDF
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)
    signedData, _ := pdfSigner.SignPdf(pdfReader)
}
```

### Cloud Signing with CSC API

```go
package main

import (
    "context"
    "net/http"
    "os"

    "github.com/georgepadayatti/gopdf/sign/signers"
    "github.com/georgepadayatti/gopdf/sign/timestamps"
)

func main() {
    ctx := context.Background()
    httpClient := &http.Client{}

    // Create CSC session
    sessionInfo := signers.NewCSCServiceSessionInfo(
        "https://csc-service.example.com",
        "credential-id",
    )
    sessionInfo.WithOAuthToken("access-token")

    // Fetch certificates
    credInfo, _ := signers.FetchCertsInCSCCredential(ctx, httpClient, sessionInfo)

    // Create authorization with pre-fetched SAD
    authInfo := &signers.CSCAuthorizationInfo{SAD: "sad-token"}
    authManager := signers.NewPrefetchedSADAuthorizationManager(
        sessionInfo, credInfo, authInfo,
    )

    // Create CSC signer
    signer := signers.NewCSCSigner(authManager, httpClient)
    cmsSigner := signers.NewCMSSignerAdapter(signer, "sha256")

    // Add timestamp (optional)
    opts := signers.DefaultSignPdfOptions()
    opts.Timestamper = timestamps.NewHTTPTimestamper("https://tsa.example.com")

    // Sign PDF
    pdfData, _ := os.ReadFile("document.pdf")
    metadata := signers.NewSignatureMetadata("Signature1")
    signedData, _ := signers.SignPdfBytes(pdfData, metadata, cmsSigner, opts)
}
```

### Add Watermark to PDF

```go
package main

import (
    "bytes"
    "os"

    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/pdf/writer"
    "github.com/georgepadayatti/gopdf/stamp"
)

func main() {
    pdfData, _ := os.ReadFile("document.pdf")
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)

    // Create watermark
    watermark := stamp.NewWatermark("CONFIDENTIAL")
    watermark.Rotation = -45           // Diagonal
    watermark.Opacity = 0.3            // 30% opacity
    watermark.Style.FontSize = 72      // Large text

    // Create incremental writer
    incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

    // Create a stamper (see docs/watermarks.md for full implementation)
    stamper := createWatermarkStamper(watermark, 612, 792) // Letter size

    // Apply watermark using ApplyStampWithPageTransform
    stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, 0, 0, 0, nil)

    // Write output
    var buf bytes.Buffer
    incWriter.Write(&buf)
    os.WriteFile("document_watermarked.pdf", buf.Bytes(), 0644)
}

// See docs/watermarks.md for the full watermarkStamper implementation
```

## Documentation

Comprehensive documentation is available in the `docs/` folder:

- [Signing Guide](docs/signing.md) - Complete guide to PDF signing including ETSI compliance
- [Timestamps](docs/timestamps.md) - RFC 3161 timestamp integration
- [Visual Signatures](docs/visual-signatures.md) - Signature appearances and stamps
- [Watermarks](docs/watermarks.md) - Adding watermarks to PDFs
- [Examples](docs/examples.md) - Additional code examples

## Supported Signature Types

| Type | SubFilter | Description |
|------|-----------|-------------|
| PAdES | `adbe.pkcs7.detached` | Standard Adobe PDF signature |
| CAdES | `ETSI.CAdES.detached` | ETSI-compliant CMS signature |
| Timestamp | `ETSI.RFC3161` | Document timestamp |

## Signature Algorithms

- RSA: SHA256, SHA384, SHA512, RSA-PSS variants
- ECDSA: SHA256, SHA384, SHA512
- EdDSA (Ed25519)

## Key Sources

| Source | Package | Description |
|--------|---------|-------------|
| PEM Files | `crypto/x509` | Standard PEM-encoded certificates and keys |
| PKCS#12 | `go-pkcs12` | P12/PFX bundles with certificate chains |
| PKCS#11 | `signers.PKCS11Signer` | Hardware tokens (HSM, smart cards) |
| CSC API | `signers.CSCSigner` | Cloud Signature Consortium remote signing |
| External | `signers.ExternalSigner` | Custom signing callbacks |

## Project Structure

```
gopdf/
├── pdf/              # PDF reading, writing, and manipulation
│   ├── reader/       # PDF parsing
│   ├── writer/       # PDF creation and incremental updates
│   ├── generic/      # PDF object types
│   ├── images/       # Image handling for PDF
│   └── embed/        # File embedding
├── sign/             # Digital signing and validation
│   ├── signers/      # Signer implementations
│   ├── cms/          # CMS/PKCS#7 structures
│   ├── ades/         # Advanced Electronic Signatures
│   ├── dss/          # Document Security Store
│   ├── validation/   # Signature validation
│   ├── timestamps/   # RFC 3161 timestamps
│   └── fields/       # Signature field handling
├── stamp/            # Visual signatures and stamps
├── certvalidator/    # X.509 certificate validation
├── cli/              # Command-line interface
├── examples/         # Working examples
└── testdata/         # Test certificates and PDFs
```

## Command Line Interface

```bash
# Sign a PDF
gopdf sign -input document.pdf -output signed.pdf -cert signer.p12 -password secret

# Verify signatures
gopdf verify -input signed.pdf -ca ca.crt

# Show version
gopdf version
```

## Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...
```

## Requirements

- Go 1.24.0 or later

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## Related Standards

- [ETSI TS 103 171](https://www.etsi.org/) - PAdES Baseline Profiles
- [ETSI TS 103 182](https://www.etsi.org/) - CAdES Baseline Profiles
- [RFC 3161](https://tools.ietf.org/html/rfc3161) - Time-Stamp Protocol
- [RFC 5652](https://tools.ietf.org/html/rfc5652) - Cryptographic Message Syntax
- [ISO 32000-2](https://www.iso.org/) - PDF 2.0 Specification
- [Cloud Signature Consortium](https://cloudsignatureconsortium.org/) - CSC API Specification
