# Visual Signatures and Stamps

This guide covers creating visual signature appearances and stamps in PDF documents.

Disclaimer: This is a fun experiment; use at your peril. It is not intended for production use.

## Table of Contents

- [Overview](#overview)
- [Text Stamps](#text-stamps)
- [Visual Signatures](#visual-signatures)
- [Image Stamps](#image-stamps)
- [QR Code Stamps](#qr-code-stamps)
- [Signature Appearance Builder](#signature-appearance-builder)
- [Applying Stamps to PDFs](#applying-stamps-to-pdfs)

## Overview

gopdf provides several stamp types for visual representation:

| Type | Description | Use Case |
|------|-------------|----------|
| TextStamp | Multi-line text | Simple annotations |
| SignatureAppearance | Signature metadata display | Visible signature fields |
| VisualSignature | Image + text combination | Rich signature appearances |
| ImageStamp | Image only | Logos, stamps |
| QRStamp | QR code | Verification links |
| QRTextStamp | QR code + text | QR with description |
| Watermark | Rotated overlay text | Document marking |

## Text Stamps

### Basic Text Stamp

```go
import "github.com/georgepadayatti/gopdf/stamp"

// Create simple text stamp
lines := []string{
    "Reviewed by: John Doe",
    "Date: 2024-01-15",
    "Status: Approved",
}
textStamp := stamp.NewTextStamp(lines, nil)  // nil uses default style

// Get dimensions
width, height := textStamp.GetDimensions()
```

### Styled Text Stamp

```go
import (
    "image/color"
    "github.com/georgepadayatti/gopdf/stamp"
)

// Create custom style
style := &stamp.StampStyle{
    BackgroundColor: color.RGBA{255, 255, 200, 255},  // Light yellow
    BorderColor:     color.RGBA{0, 0, 0, 255},        // Black border
    BorderWidth:     2.0,
    TextColor:       color.RGBA{0, 0, 128, 255},      // Navy blue
    FontSize:        12.0,
    FontName:        "Helvetica-Bold",
    Padding:         10.0,
}

lines := []string{
    "APPROVED",
    "Manager Signature",
}
textStamp := stamp.NewTextStamp(lines, style)
```

## Visual Signatures

### Basic Visual Signature

```go
import (
    "time"
    "github.com/georgepadayatti/gopdf/stamp"
)

config := stamp.DefaultVisualSignatureConfig()
config.SignerName = "John Doe"
config.Reason = "Document approval"
config.Location = "Berlin, Germany"
config.SigningTime = time.Now()

// Control what's displayed
config.ShowSignerName = true
config.ShowDate = true
config.ShowReason = true
config.ShowLocation = true
config.ShowContact = false

// Create visual signature (200x70 points)
vs, err := stamp.NewVisualSignature(200, 70, config)
if err != nil {
    log.Fatal(err)
}
```

### Visual Signature with Image

```go
import (
    "os"
    "github.com/georgepadayatti/gopdf/stamp"
)

config := stamp.DefaultVisualSignatureConfig()
config.SignerName = "John Doe"
config.Reason = "Contract approval"

// Add signature image
imageData, _ := os.ReadFile("signature.png")
config.Image = imageData

// Image positioning options
config.ImagePosition = stamp.ImageTextPositionLeft  // Image on left, text on right
config.ImageRatio = 0.4      // Image takes 40% of width
config.ImageOpacity = 1.0    // Fully opaque
config.Separation = 5.0      // 5pt gap between image and text

vs, _ := stamp.NewVisualSignature(250, 80, config)
```

### Image Position Options

```go
const (
    ImageTextPositionLeft       // Image left, text right
    ImageTextPositionRight      // Text left, image right
    ImageTextPositionAbove      // Image above text
    ImageTextPositionBelow      // Text above image
    ImageTextPositionBackground // Image as background (watermark mode)
)
```

### Image as Watermark Background

```go
config := stamp.DefaultVisualSignatureConfig()
config.SignerName = "John Doe"
config.Image = imageData
config.ImagePosition = stamp.ImageTextPositionBackground
config.ImageOpacity = 0.3  // Semi-transparent background

// Text will overlay the image
vs, _ := stamp.NewVisualSignature(200, 100, config)
```

## Image Stamps

### Basic Image Stamp

```go
import "github.com/georgepadayatti/gopdf/stamp"

imageData, _ := os.ReadFile("company_logo.png")

// Create image stamp (200x100 points)
style := stamp.DefaultImageStampStyle()
imgStamp, err := stamp.NewImageStamp(imageData, 200, 100, style)
if err != nil {
    log.Fatal(err)
}
```

### Image Scale Modes

```go
const (
    ImageScaleFit     // Scale to fit, maintain aspect ratio
    ImageScaleFill    // Scale to fill, may crop
    ImageScaleStretch // Stretch to exact dimensions
    ImageScaleNone    // Use natural image size
)

style := stamp.DefaultImageStampStyle()
style.ScaleMode = stamp.ImageScaleFit
```

### Image Position Options

```go
const (
    ImagePositionCenter      // Center of stamp
    ImagePositionTopLeft     // Top-left corner
    ImagePositionTopRight    // Top-right corner
    ImagePositionBottomLeft  // Bottom-left corner
    ImagePositionBottomRight // Bottom-right corner
    ImagePositionLeft        // Left center
    ImagePositionRight       // Right center
    ImagePositionTop         // Top center
    ImagePositionBottom      // Bottom center
)

style := stamp.DefaultImageStampStyle()
style.Position = stamp.ImagePositionCenter
style.Opacity = 0.8
style.Padding = 5.0
```

### Image with Border

```go
import "image/color"

style := &stamp.ImageStampStyle{
    ScaleMode:       stamp.ImageScaleFit,
    Position:        stamp.ImagePositionCenter,
    Opacity:         1.0,
    BorderWidth:     2.0,
    BorderColor:     color.RGBA{0, 0, 0, 255},      // Black border
    BackgroundColor: color.RGBA{255, 255, 255, 255}, // White background
    Padding:         5.0,
}

imgStamp, _ := stamp.NewImageStamp(imageData, 150, 80, style)
```

### Image + Text Stamp

```go
import "github.com/georgepadayatti/gopdf/stamp"

imageData, _ := os.ReadFile("logo.png")
lines := []string{
    "Approved by:",
    "Quality Assurance",
    "2024-01-15",
}

style := stamp.DefaultImageTextStampStyle()
style.ImagePosition = stamp.ImageTextPositionLeft
style.ImageRatio = 0.35  // Image takes 35% of width
style.Separation = 8.0   // 8pt gap

imgTextStamp, _ := stamp.NewImageTextStamp(imageData, lines, 200, 80, style)
```

## QR Code Stamps

### Simple QR Code

```go
import "github.com/georgepadayatti/gopdf/stamp"

// Create QR code stamp (100x100 points)
qrStamp := stamp.NewQRStamp("https://example.com/verify/123", 100)

// Get dimensions
width, height := qrStamp.GetDimensions()  // 100, 100
```

### QR Code with Text

```go
import "github.com/georgepadayatti/gopdf/stamp"

url := "https://example.com/verify/doc-123"
lines := []string{
    "Scan to verify",
    "Document ID: 123",
}

style := stamp.DefaultQRStampStyle()
style.QRPosition = stamp.QRPositionLeftOfText  // QR on left
style.QRSize = 50                               // 50pt QR code
style.InnerSeparation = 5                       // 5pt gap

qrTextStamp := stamp.NewQRTextStamp(url, lines, style)
```

### QR Position Options

```go
const (
    QRPositionLeftOfText  // QR left, text right
    QRPositionRightOfText // Text left, QR right
    QRPositionAboveText   // QR above text
    QRPositionBelowText   // Text above QR
)

style := stamp.DefaultQRStampStyle()
style.QRPosition = stamp.QRPositionLeftOfText
```

### QR with Link Annotation

```go
// Create QR stamp
qrStamp := stamp.NewQRTextStamp(url, lines, nil)

// Create link annotation for QR code area
// When placed at position (stampX, stampY) on page
linkAnnot := qrStamp.CreateLinkAnnotation(stampX, stampY)

// Or create link covering the entire stamp
fullLinkAnnot := qrStamp.CreateFullLinkAnnotation(stampX, stampY)
```

## Signature Appearance Builder

Fluent API for building visual signatures:

```go
import (
    "image/color"
    "time"
    "github.com/georgepadayatti/gopdf/stamp"
)

imageData, _ := os.ReadFile("signature.png")

builder := stamp.NewSignatureAppearanceBuilder("John Doe", 200, 80).
    WithReason("Contract approval").
    WithLocation("Berlin, Germany").
    WithSigningTime(time.Now()).
    WithImage(imageData).
    WithImagePosition(stamp.ImageTextPositionLeft).
    WithImageRatio(0.4).
    WithBorder(1.0, color.RGBA{0, 0, 0, 255}).
    HideDate().  // Optional: hide date
    HideReason() // Optional: hide reason

vs, err := builder.Build()
if err != nil {
    log.Fatal(err)
}
```

### Builder Methods

| Method | Description |
|--------|-------------|
| `WithReason(string)` | Set signing reason |
| `WithLocation(string)` | Set signing location |
| `WithContact(string)` | Set contact info |
| `WithSigningTime(time.Time)` | Set signing time |
| `WithImage([]byte)` | Set signature image |
| `WithImageAsWatermark(float64)` | Use image as background |
| `WithImagePosition(ImageTextPosition)` | Set image position |
| `WithImageRatio(float64)` | Set image width ratio |
| `WithTextStyle(*StampStyle)` | Set text styling |
| `WithBorder(float64, color.RGBA)` | Add border |
| `HideDate()` | Don't show date |
| `HideReason()` | Don't show reason |
| `HideLocation()` | Don't show location |
| `Build()` | Create VisualSignature |

## Applying Stamps to PDFs

### Using ApplyStampWithPageTransform (Recommended)

Use `ApplyStampWithPageTransform` when applying stamps to existing PDFs. This function handles page coordinate transformations correctly (some PDFs have Y-axis flipped).

```go
import (
    "bytes"
    "os"

    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/pdf/writer"
    "github.com/georgepadayatti/gopdf/stamp"
)

// Read PDF
pdfData, _ := os.ReadFile("document.pdf")
pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)

// Create stamp
textStamp := stamp.NewTextStamp([]string{"APPROVED"}, nil)

// Create incremental writer
incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

// Apply stamp to page 0 at position (100, 700)
// Note: requires both pdfReader and incWriter
_, width, height, err := stamp.ApplyStampWithPageTransform(incWriter, pdfReader, textStamp, 0, 100, 700, nil)
if err != nil {
    log.Fatal(err)
}

// Write output
var buf bytes.Buffer
incWriter.Write(&buf)
os.WriteFile("stamped.pdf", buf.Bytes(), 0644)
```

### Using ApplyStamp (Basic)

Use `ApplyStamp` for simple cases where you don't need page transform handling:

```go
// Apply stamp without page transform handling
_, width, height, err := stamp.ApplyStamp(incWriter, textStamp, 0, 100, 700, nil)
```

### Stamp Apply Options

```go
opts := &stamp.ApplyOptions{
    WrapExistingContent: true,  // Isolate existing graphics state (default: true)
}

stamp.ApplyStampWithPageTransform(incWriter, pdfReader, textStamp, pageNum, x, y, opts)
```

### Helper Functions

```go
// Apply text stamp directly to file
err := stamp.TextStampFile(
    "input.pdf",
    "output.pdf",
    []string{"REVIEWED", "2024-01-15"},
    nil,  // default style
    0,    // page number
    50,   // x position
    750,  // y position
)

// Apply QR stamp directly to file
err := stamp.QRStampFile(
    "input.pdf",
    "output.pdf",
    "https://example.com/verify",
    []string{"Scan to verify"},
    nil,  // default style
    0,    // page number
    500,  // x position
    50,   // y position
)
```

## Signature Rectangle

### Defining Signature Position

```go
import "github.com/georgepadayatti/gopdf/stamp"

// Create signature rectangle
rect := stamp.NewSignatureRect(50, 50, 250, 120)

// LowerLeftX, LowerLeftY, UpperRightX, UpperRightY
// This creates a 200x70 point rectangle at (50, 50)

width := rect.Width()   // 200
height := rect.Height() // 70

// Convert to PDF array
pdfArray := rect.ToArray()

// Convert to generic.Rectangle
genRect := rect.ToGenericRectangle()
```

## Creating Appearance Streams

All stamp types implement appearance stream creation:

```go
// Get PDF appearance stream
appearanceStream := textStamp.CreateAppearanceStream()

// For visual signatures with images
formStream, imageStreams, err := vs.CreateAppearanceStream()
if err != nil {
    log.Fatal(err)
}

// formStream is the main appearance
// imageStreams contains image XObject streams
```

## Complete Example: Visible Signature

```go
package main

import (
    "os"
    "time"

    "github.com/georgepadayatti/gopdf/pdf/generic"
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/sign/cms"
    "github.com/georgepadayatti/gopdf/sign/signers"
    "github.com/georgepadayatti/gopdf/stamp"
    "software.sslmate.com/src/go-pkcs12"
)

func main() {
    // Load certificate
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

    // Create PDF signer
    pdfSigner := signers.NewPdfSigner(signer, metadata)

    // Set visible signature position
    rect := &generic.Rectangle{
        LLX: 50,
        LLY: 50,
        URX: 250,
        URY: 120,
    }
    pdfSigner.SetSignatureAppearance(0, rect)

    // Read and sign PDF
    pdfData, _ := os.ReadFile("document.pdf")
    pdfReader, _ := reader.NewPdfFileReaderFromBytes(pdfData)
    signedData, _ := pdfSigner.SignPdf(pdfReader)

    // Save signed PDF
    os.WriteFile("signed_visible.pdf", signedData, 0644)
}
```
