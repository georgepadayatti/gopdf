# Code Examples

This document provides additional code examples for common use cases with gopdf.

Disclaimer: This is a fun experiment; use at your peril. It is not intended for production use.

## Table of Contents

- [Basic Signing Examples](#basic-signing-examples)
- [Visual Signature Examples](#visual-signature-examples)
- [Watermark Examples](#watermark-examples)
- [Stamp Examples](#stamp-examples)
- [Verification Examples](#verification-examples)
- [Advanced Examples](#advanced-examples)

## Basic Signing Examples

### Sign PDF with PEM Files

```go
package main

import (
    "crypto"
    "crypto/x509"
    "encoding/pem"
    "log"
    "os"

    "github.com/georgepadayatti/gopdf/sign/cms"
    "github.com/georgepadayatti/gopdf/sign/signers"
)

func main() {
    // Load certificate
    certPEM, _ := os.ReadFile("signer.crt")
    certBlock, _ := pem.Decode(certPEM)
    cert, _ := x509.ParseCertificate(certBlock.Bytes)

    // Load private key
    keyPEM, _ := os.ReadFile("signer.key")
    keyBlock, _ := pem.Decode(keyPEM)
    key, _ := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)

    // Create signer
    signer := signers.NewSimpleSigner(cert, key.(crypto.Signer), cms.SHA256WithRSA)

    // Create metadata
    metadata := signers.NewSignatureMetadata("Signature1")
    metadata.Reason = "Document approval"
    metadata.Location = "Berlin"
    metadata.Name = cert.Subject.CommonName

    // Sign PDF
    pdfData, _ := os.ReadFile("document.pdf")
    signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, nil)
    if err != nil {
        log.Fatal(err)
    }

    os.WriteFile("signed.pdf", signedData, 0644)
    log.Println("PDF signed successfully")
}
```

### Sign PDF with PKCS#12

```go
package main

import (
    "crypto"
    "log"
    "os"

    "github.com/georgepadayatti/gopdf/sign/cms"
    "github.com/georgepadayatti/gopdf/sign/signers"
    "software.sslmate.com/src/go-pkcs12"
)

func main() {
    // Load PKCS#12 file
    p12Data, _ := os.ReadFile("signer.p12")
    key, cert, chain, err := pkcs12.DecodeChain(p12Data, "password")
    if err != nil {
        log.Fatal(err)
    }

    // Create signer with certificate chain
    signer := signers.NewSimpleSigner(cert, key.(crypto.Signer), cms.SHA256WithRSA)
    signer.SetCertificateChain(chain)

    // Sign
    pdfData, _ := os.ReadFile("document.pdf")
    metadata := signers.NewSignatureMetadata("Signature1")
    signedData, _ := signers.SignPdfBytes(pdfData, metadata, signer, nil)

    os.WriteFile("signed.pdf", signedData, 0644)
}
```

### Sign with Timestamp

```go
package main

import (
    "log"
    "os"

    "github.com/georgepadayatti/gopdf/sign/signers"
    "github.com/georgepadayatti/gopdf/sign/timestamps"
)

func main() {
    // ... create signer ...

    // Create timestamper
    timestamper := timestamps.NewHTTPTimestamper("https://freetsa.org/tsr")

    // Sign with timestamp
    opts := signers.DefaultSignPdfOptions()
    opts.Timestamper = timestamper

    signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, opts)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("PDF signed with timestamp")
}
```

## Visual Signature Examples

### Basic Visible Signature

```go
package main

import (
    "log"
    "os"

    "github.com/georgepadayatti/gopdf/pdf/generic"
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/sign/signers"
)

func main() {
    // ... create signer and metadata ...

    // Create PDF signer
    pdfSigner := signers.NewPdfSigner(signer, metadata)

    // Add visible signature on first page
    rect := &generic.Rectangle{
        LLX: 50,   // Left
        LLY: 50,   // Bottom
        URX: 200,  // Right
        URY: 100,  // Top
    }
    pdfSigner.SetSignatureAppearance(0, rect)

    // Sign
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)
    signedData, _ := pdfSigner.SignPdf(pdfReader)

    os.WriteFile("signed_visible.pdf", signedData, 0644)
}
```

### Signature with Logo Image

```go
package main

import (
    "os"
    "time"

    "github.com/georgepadayatti/gopdf/stamp"
)

func main() {
    // Load logo image
    logoData, _ := os.ReadFile("company_logo.png")

    // Create visual signature config
    config := stamp.DefaultVisualSignatureConfig()
    config.SignerName = "John Doe"
    config.Reason = "Contract approval"
    config.Location = "Berlin, Germany"
    config.SigningTime = time.Now()

    // Add image on left side
    config.Image = logoData
    config.ImagePosition = stamp.ImageTextPositionLeft
    config.ImageRatio = 0.35

    // Create visual signature
    vs, err := stamp.NewVisualSignature(200, 70, config)
    if err != nil {
        panic(err)
    }

    // Get appearance stream for use in signature
    appearanceStream, imageStreams, _ := vs.CreateAppearanceStream()
    _ = appearanceStream
    _ = imageStreams
}
```

## Watermark Examples

### Add Diagonal Watermark

```go
package main

import (
    "bytes"
    "image/color"
    "os"

    "github.com/georgepadayatti/gopdf/pdf/generic"
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/pdf/writer"
    "github.com/georgepadayatti/gopdf/stamp"
)

// watermarkStamper implements the Stamper interface
type watermarkStamper struct {
    watermark *stamp.Watermark
    width, height float64
}

func (w *watermarkStamper) CreateAppearanceStream() *generic.StreamObject {
    content := w.watermark.Render(w.width, w.height)
    dict := generic.NewDictionary()
    dict.Set("Type", generic.NameObject("XObject"))
    dict.Set("Subtype", generic.NameObject("Form"))
    dict.Set("BBox", generic.ArrayObject{
        generic.RealObject(0), generic.RealObject(0),
        generic.RealObject(w.width), generic.RealObject(w.height),
    })
    resources := generic.NewDictionary()
    extGState := generic.NewDictionary()
    extGState.Set("GS1", w.watermark.CreateExtGState())
    resources.Set("ExtGState", extGState)
    fonts := generic.NewDictionary()
    font := generic.NewDictionary()
    font.Set("Type", generic.NameObject("Font"))
    font.Set("Subtype", generic.NameObject("Type1"))
    font.Set("BaseFont", generic.NameObject(w.watermark.Style.FontName))
    fonts.Set("F1", font)
    resources.Set("Font", fonts)
    dict.Set("Resources", resources)
    return generic.NewStream(dict, content)
}

func (w *watermarkStamper) GetDimensions() (float64, float64) {
    return w.width, w.height
}

func main() {
    // Read PDF
    pdfData, _ := os.ReadFile("document.pdf")
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)

    // Create watermark
    watermark := stamp.NewWatermark("CONFIDENTIAL")
    watermark.Rotation = -45
    watermark.Opacity = 0.15
    watermark.Style.FontSize = 72
    watermark.Style.TextColor = color.RGBA{128, 128, 128, 255}

    // Create incremental writer
    incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

    // Get page dimensions (helper function needed - see watermarks.md)
    pageWidth, pageHeight := 612.0, 792.0 // Default letter size

    // Create stamper and apply
    stamper := &watermarkStamper{watermark: watermark, width: pageWidth, height: pageHeight}
    stamp.ApplyStampWithPageTransform(incWriter, pdfReader, stamper, 0, 0, 0, nil)

    // Write output
    var buf bytes.Buffer
    incWriter.Write(&buf)
    os.WriteFile("watermarked.pdf", buf.Bytes(), 0644)
}
```

### Draft Watermark

```go
package main

import (
    "image/color"

    "github.com/georgepadayatti/gopdf/stamp"
)

func main() {
    watermark := stamp.NewWatermark("DRAFT")
    watermark.Rotation = -30     // Less steep angle
    watermark.Opacity = 0.2      // Subtle

    watermark.Style = &stamp.StampStyle{
        FontSize:  96,
        FontName:  "Helvetica-Bold",
        TextColor: color.RGBA{255, 0, 0, 255},  // Red
    }

    // Render for a letter-size page (612x792 points)
    content := watermark.Render(612, 792)
    _ = content
}
```

## Stamp Examples

### Text Stamp

```go
package main

import (
    "image/color"

    "github.com/georgepadayatti/gopdf/stamp"
)

func main() {
    // Create styled text stamp
    style := &stamp.StampStyle{
        BackgroundColor: color.RGBA{255, 255, 200, 255},  // Light yellow
        BorderColor:     color.RGBA{0, 0, 0, 255},        // Black
        BorderWidth:     1.5,
        TextColor:       color.RGBA{0, 0, 128, 255},      // Navy
        FontSize:        11,
        FontName:        "Helvetica",
        Padding:         8,
    }

    lines := []string{
        "APPROVED",
        "Reviewed by: John Doe",
        "Date: 2024-01-15",
    }

    textStamp := stamp.NewTextStamp(lines, style)

    // Apply to PDF at position (400, 700)
    stamp.TextStampFile("input.pdf", "output.pdf", lines, style, 0, 400, 700)
}
```

### QR Code Stamp with Verification Link

```go
package main

import "github.com/georgepadayatti/gopdf/stamp"

func main() {
    // Create QR stamp with verification URL
    url := "https://verify.example.com/doc/ABC123"
    lines := []string{
        "Scan to verify",
        "Doc ID: ABC123",
    }

    style := stamp.DefaultQRStampStyle()
    style.QRPosition = stamp.QRPositionLeftOfText
    style.QRSize = 60

    qrStamp := stamp.NewQRTextStamp(url, lines, style)

    // Apply to PDF
    stamp.QRStampFile("input.pdf", "output.pdf", url, lines, style, 0, 50, 50)
}
```

### Image Stamp

```go
package main

import (
    "image/color"
    "os"

    "github.com/georgepadayatti/gopdf/stamp"
)

func main() {
    imageData, _ := os.ReadFile("approved_stamp.png")

    style := &stamp.ImageStampStyle{
        ScaleMode:       stamp.ImageScaleFit,
        Position:        stamp.ImagePositionCenter,
        Opacity:         0.8,
        BorderWidth:     2,
        BorderColor:     color.RGBA{0, 128, 0, 255},  // Green border
        BackgroundColor: color.RGBA{255, 255, 255, 255},
        Padding:         5,
    }

    imgStamp, _ := stamp.NewImageStamp(imageData, 150, 80, style)

    width, height := imgStamp.GetDimensions()
    _ = width
    _ = height
}
```

## Verification Examples

### Verify PDF Signatures

```go
package main

import (
    "crypto/x509"
    "fmt"
    "log"
    "os"

    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/sign/cms"
)

func main() {
    // Load CA certificate
    caCertPEM, _ := os.ReadFile("ca.crt")
    caCertBlock, _ := pem.Decode(caCertPEM)
    caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)

    // Read signed PDF
    pdfData, _ := os.ReadFile("signed.pdf")
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)

    // Get signatures
    signatures, err := pdfReader.GetEmbeddedSignatures()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d signatures\n", len(signatures))

    for i, sig := range signatures {
        fmt.Printf("\nSignature %d:\n", i+1)

        // Get signature data
        signatureBytes := sig.Contents
        signedData := sig.GetSignedData()

        // Verify integrity
        if err := cms.VerifyCMSSignature(signatureBytes, signedData); err != nil {
            fmt.Printf("  Integrity: INVALID (%v)\n", err)
            continue
        }
        fmt.Println("  Integrity: VALID")

        // Get signer certificate
        certs, _ := cms.GetSignerCertificates(signatureBytes)
        if len(certs) > 0 {
            fmt.Printf("  Signer: %s\n", certs[0].Subject.CommonName)

            // Verify certificate chain
            roots := x509.NewCertPool()
            roots.AddCert(caCert)

            _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots})
            if err != nil {
                fmt.Printf("  Certificate: INVALID (%v)\n", err)
            } else {
                fmt.Println("  Certificate: VALID")
            }
        }

        // Print metadata
        fmt.Printf("  Reason: %s\n", sig.GetReason())
        fmt.Printf("  Location: %s\n", sig.GetLocation())
        fmt.Printf("  Time: %s\n", sig.GetSigningTime())
    }
}
```

## Advanced Examples

### Multiple Signatures

```go
package main

import (
    "os"

    "github.com/georgepadayatti/gopdf/pdf/generic"
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/sign/signers"
)

func main() {
    // First signature
    pdfData, _ := os.ReadFile("document.pdf")

    metadata1 := signers.NewSignatureMetadata("Signature1")
    metadata1.Reason = "Author signature"
    signedData1, _ := signers.SignPdfBytes(pdfData, metadata1, signer1, nil)

    // Second signature (on already-signed PDF)
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(signedData1)

    metadata2 := signers.NewSignatureMetadata("Signature2")
    metadata2.Reason = "Approval signature"

    pdfSigner2 := signers.NewPdfSigner(signer2, metadata2)

    // Different position for second signature
    rect := &generic.Rectangle{LLX: 300, LLY: 50, URX: 450, URY: 100}
    pdfSigner2.SetSignatureAppearance(0, rect)

    signedData2, _ := pdfSigner2.SignPdf(pdfReader)

    os.WriteFile("multi_signed.pdf", signedData2, 0644)
}
```

### Batch Signing

```go
package main

import (
    "fmt"
    "os"
    "path/filepath"

    "github.com/georgepadayatti/gopdf/sign/signers"
)

func main() {
    // ... create signer ...

    // Find all PDFs in directory
    files, _ := filepath.Glob("documents/*.pdf")

    for _, inputPath := range files {
        pdfData, err := os.ReadFile(inputPath)
        if err != nil {
            fmt.Printf("Error reading %s: %v\n", inputPath, err)
            continue
        }

        metadata := signers.NewSignatureMetadata("BatchSignature")
        metadata.Reason = "Batch processing"

        signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, nil)
        if err != nil {
            fmt.Printf("Error signing %s: %v\n", inputPath, err)
            continue
        }

        outputPath := filepath.Join("signed", filepath.Base(inputPath))
        os.WriteFile(outputPath, signedData, 0644)
        fmt.Printf("Signed: %s\n", outputPath)
    }
}
```

### Custom External Signing

```go
package main

import (
    "crypto"
    "crypto/rsa"

    "github.com/georgepadayatti/gopdf/sign/cms"
    "github.com/georgepadayatti/gopdf/sign/signers"
)

func main() {
    // Custom signing function (e.g., HSM, remote service)
    customSign := func(digest []byte) ([]byte, error) {
        // Example: Sign using RSA PKCS#1 v1.5
        // In reality, this would call your HSM or service
        signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, digest)
        return signature, err
    }

    // Create external signer
    externalSigner := signers.NewExternalSigner(cert, customSign, cms.SHA256WithRSA)
    externalSigner.CertChain = chain

    // Use like any other signer
    signedData, _ := signers.SignPdfBytes(pdfData, metadata, externalSigner, nil)
    _ = signedData
}
```

### Pre-Sign Validation

```go
package main

import (
    "fmt"

    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/sign/signers"
)

func main() {
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)

    pdfSigner := signers.NewPdfSigner(signer, metadata)

    // Create signing session
    session := signers.NewPdfSigningSession(pdfSigner, pdfReader)

    // Validate before signing
    status := session.ValidatePreSign()

    if !status.SignerCertValid {
        fmt.Println("Certificate is not valid!")
        for _, err := range status.Errors {
            fmt.Printf("  Error: %v\n", err)
        }
        return
    }

    // Proceed with signing
    signedData, err := session.Sign()
    if err != nil {
        fmt.Printf("Signing failed: %v\n", err)
        return
    }

    _ = signedData
}
```
