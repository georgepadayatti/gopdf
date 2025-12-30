# RFC 3161 Timestamps

This guide covers timestamp integration in gopdf for creating time-stamped signatures and document timestamps.

Disclaimer: This is a fun experiment; use at your peril. It is not intended for production use.

## Table of Contents

- [Overview](#overview)
- [Timestamp Types](#timestamp-types)
- [Using HTTP Timestamper](#using-http-timestamper)
- [Signature Timestamps](#signature-timestamps)
- [Document Timestamps](#document-timestamps)
- [Timestamp Verification](#timestamp-verification)
- [Public TSA Servers](#public-tsa-servers)

## Overview

RFC 3161 timestamps provide cryptographic proof that data existed at a specific point in time. In PDF signing, timestamps serve two purposes:

1. **Signature Timestamps**: Prove when a signature was created
2. **Document Timestamps**: Prove the document existed at a specific time

## Timestamp Types

| Type | PDF SubFilter | Description |
|------|---------------|-------------|
| Signature Timestamp | Embedded in CMS | Timestamp token embedded in signature |
| Document Timestamp | `ETSI.RFC3161` | Standalone timestamp for entire document |

## Using HTTP Timestamper

### Basic Usage

```go
import "github.com/georgepadayatti/gopdf/sign/timestamps"

// Create HTTP timestamper
timestamper := timestamps.NewHTTPTimestamper("https://freetsa.org/tsr")

// Get timestamp for data
data := []byte("data to timestamp")
timestampToken, err := timestamper.Timestamp(data)
if err != nil {
    log.Fatalf("Timestamp failed: %v", err)
}
```

### With Authentication

```go
// Create timestamper with credentials
timestamper := timestamps.NewHTTPTimestamper("https://tsa.example.com")
timestamper.SetCredentials("username", "password")

// Custom HTTP client with timeout
timestamper.HTTPClient = &http.Client{
    Timeout: 30 * time.Second,
}
```

### Custom Options

```go
// Configure timestamp request options
opts := &timestamps.TimestampRequestOptions{
    HashAlgorithm: crypto.SHA384,      // Use SHA-384 instead of default SHA-256
    IncludeNonce:  true,               // Include nonce for replay protection
    RequestCerts:  true,               // Request TSA certificates in response
    Policy:        asn1.ObjectIdentifier{1, 2, 3, 4},  // Optional policy OID
}

// Timestamp with custom options
token, err := timestamper.TimestampWithOptions(data, opts)
```

## Signature Timestamps

### Adding Timestamp to Signature

```go
import (
    "github.com/georgepadayatti/gopdf/sign/signers"
    "github.com/georgepadayatti/gopdf/sign/timestamps"
)

// Create timestamper
timestamper := timestamps.NewHTTPTimestamper("https://freetsa.org/tsr")

// Configure signing options with timestamp
opts := signers.DefaultSignPdfOptions()
opts.Timestamper = timestamper

// Sign PDF with embedded timestamp
signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, opts)
```

### Timestamp in CAdES Signature

When using `ETSI.CAdES.detached` SubFilter, the timestamp is embedded as an unsigned attribute in the CMS structure:

```go
metadata := signers.NewSignatureMetadata("Signature1")
metadata.SubFilter = "ETSI.CAdES.detached"  // Required for CAdES timestamp

opts := signers.DefaultSignPdfOptions()
opts.Timestamper = timestamper

signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, opts)
```

## Document Timestamps

Document timestamps create a new signature field containing only a timestamp token, proving the document existed at that time.

### Adding Document Timestamp

```go
import (
    "github.com/georgepadayatti/gopdf/pdf/reader"
    "github.com/georgepadayatti/gopdf/sign/signers"
    "github.com/georgepadayatti/gopdf/sign/timestamps"
)

// Parse signed PDF
pdfReader, _ := reader.NewPdfFileReaderFromBytes(signedPdfData)

// Create timestamper
timestamper := timestamps.NewHTTPTimestamper("https://freetsa.org/tsr")

// Create PDF timestamper
pdfTimestamper := signers.NewPdfTimeStamper(timestamper)

// Add document timestamp
timestampedData, err := pdfTimestamper.AddDocumentTimestamp(pdfReader)
if err != nil {
    log.Fatalf("Failed to add document timestamp: %v", err)
}
```

### Document Timestamp Structure

The document timestamp creates a signature field with:

```
/Type /DocTimeStamp
/SubFilter /ETSI.RFC3161
/Contents <timestamp_token_hex>
/ByteRange [...]
```

## Timestamp Verification

### Extracting Timestamp Information

```go
// Parse timestamp token
token, err := timestamps.ParseTimestampToken(tokenData)
if err != nil {
    log.Fatalf("Failed to parse timestamp: %v", err)
}

// Access timestamp info
fmt.Printf("Generation Time: %s\n", token.TSTInfo.GenTime)
fmt.Printf("Serial Number: %s\n", token.TSTInfo.SerialNumber)
fmt.Printf("Policy: %v\n", token.TSTInfo.Policy)

// Accuracy
if token.TSTInfo.Accuracy.Seconds > 0 {
    fmt.Printf("Accuracy: %d seconds\n", token.TSTInfo.Accuracy.Seconds)
}
```

### Verifying Timestamp

```go
// Verify timestamp against original data
err := timestamps.VerifyTimestamp(tokenData, originalData)
if err != nil {
    if errors.Is(err, timestamps.ErrTimestampMismatch) {
        log.Println("Timestamp does not match data")
    } else {
        log.Fatalf("Verification failed: %v", err)
    }
}
```

### Getting Timestamp Generation Time

```go
genTime, err := timestamps.GetGenTime(tokenData)
if err != nil {
    log.Fatalf("Failed to get timestamp time: %v", err)
}
fmt.Printf("Document timestamped at: %s\n", genTime.Format(time.RFC3339))
```

## Creating Timestamp Requests Manually

```go
// Create timestamp request
requestBytes, err := timestamps.CreateTimestampRequest(data, &timestamps.TimestampRequestOptions{
    HashAlgorithm: crypto.SHA256,
    IncludeNonce:  true,
    RequestCerts:  true,
})
if err != nil {
    log.Fatalf("Failed to create request: %v", err)
}

// Send request to TSA
req, _ := http.NewRequest("POST", "https://freetsa.org/tsr", bytes.NewReader(requestBytes))
req.Header.Set("Content-Type", "application/timestamp-query")

resp, _ := http.DefaultClient.Do(req)
respBytes, _ := io.ReadAll(resp.Body)

// Parse and validate response
token, err := timestamps.ParseTimestampResponse(respBytes, data, crypto.SHA256)
if err != nil {
    log.Fatalf("Invalid response: %v", err)
}
```

## Timestamp Token Structure

RFC 3161 timestamp tokens contain:

| Field | Description |
|-------|-------------|
| Version | Token format version (typically 1) |
| Policy | TSA's policy OID |
| MessageImprint | Hash of timestamped data |
| SerialNumber | Unique token identifier |
| GenTime | Generation timestamp |
| Accuracy | Optional timestamp accuracy |
| Nonce | Optional replay protection value |
| Certificates | Optional TSA certificate chain |

## Public TSA Servers

### Free TSA Servers

| Provider | URL | Notes |
|----------|-----|-------|
| FreeTSA | `https://freetsa.org/tsr` | Free, no registration |
| DigiCert | `http://timestamp.digicert.com` | Free, no registration |
| Sectigo | `http://timestamp.sectigo.com` | Free, no registration |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | Free |

### Using Multiple TSA Servers

```go
// Try multiple TSA servers with fallback
tsaURLs := []string{
    "https://freetsa.org/tsr",
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
}

var token []byte
var err error

for _, url := range tsaURLs {
    timestamper := timestamps.NewHTTPTimestamper(url)
    token, err = timestamper.Timestamp(data)
    if err == nil {
        break
    }
    log.Printf("TSA %s failed: %v", url, err)
}

if token == nil {
    log.Fatal("All TSA servers failed")
}
```

## Error Handling

### Common Errors

```go
import "github.com/georgepadayatti/gopdf/sign/timestamps"

switch {
case errors.Is(err, timestamps.ErrTimestampFailed):
    // Network or HTTP error
    log.Println("Timestamp request failed")

case errors.Is(err, timestamps.ErrTimestampRejected):
    // TSA rejected the request
    log.Println("Timestamp request rejected by TSA")

case errors.Is(err, timestamps.ErrInvalidTimestamp):
    // Invalid response format
    log.Println("Invalid timestamp response")

case errors.Is(err, timestamps.ErrTimestampMismatch):
    // Response doesn't match request
    log.Println("Timestamp mismatch - wrong data")
}
```

## Best Practices

1. **Use HTTPS**: Always use HTTPS TSA endpoints when possible
2. **Include Nonce**: Enable nonce for replay attack protection
3. **Request Certificates**: Include TSA certificates for validation
4. **Handle Failures**: Implement retry logic with multiple TSA servers
5. **Validate Responses**: Always validate timestamp tokens before trusting
6. **Consider Accuracy**: Account for timestamp accuracy in time-sensitive applications

## DSS Integration for LTV

For Long-Term Validation, timestamp information should be stored in the DSS:

```go
// Configure DSS settings for timestamp
dssSettings := signers.NewTimestampDSSContentSettings()
dssSettings.UpdateBeforeTS = true  // Update DSS before timestamping
dssSettings.IncludeVRI = true      // Include Validation Related Information

pdfTimestamper := signers.NewPdfTimeStamper(timestamper)
pdfTimestamper.DSSSettings = dssSettings
```
