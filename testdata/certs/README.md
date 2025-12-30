# Test Certificates

This directory contains test certificates for PDF signing examples.

## Certificate Structure

```
ca.crt          - Root CA certificate (self-signed)
ca.key          - Root CA private key
signer.crt      - Signer certificate (signed by CA)
signer.key      - Signer private key
signer.p12      - PKCS#12 bundle (signer cert + key + CA cert)
```

## OpenSSL Commands Used

### 1. Create Root CA

```bash
# Generate CA private key (2048-bit RSA)
openssl genrsa -out ca.key 2048

# Create self-signed CA certificate (valid for 10 years)
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=GoPDF Test CA/CN=GoPDF Test Root CA"
```

### 2. Create Signer Certificate

```bash
# Generate signer private key
openssl genrsa -out signer.key 2048

# Create Certificate Signing Request (CSR)
openssl req -new -key signer.key -out signer.csr \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=GoPDF Test/CN=GoPDF Test Signer"

# Sign the CSR with the CA (valid for 1 year)
openssl x509 -req -in signer.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out signer.crt -days 365 -sha256
```

### 3. Create PKCS#12 Bundle

```bash
# Bundle signer cert, key, and CA cert into a P12 file
# Password: test123
openssl pkcs12 -export -out signer.p12 \
  -inkey signer.key \
  -in signer.crt \
  -certfile ca.crt \
  -passout pass:test123
```

## Verify Certificates

```bash
# View CA certificate details
openssl x509 -in ca.crt -text -noout

# View signer certificate details
openssl x509 -in signer.crt -text -noout

# Verify signer certificate against CA
openssl verify -CAfile ca.crt signer.crt

# View PKCS#12 contents
openssl pkcs12 -in signer.p12 -info -passin pass:test123 -nodes
```

## Usage in Examples

The examples use these certificates for signing and verification:

```go
// Load from PKCS#12
cert, key, caCerts, err := loadP12("testdata/certs/signer.p12", "test123")

// Or load from PEM files
cert, err := loadCertPEM("testdata/certs/signer.crt")
key, err := loadKeyPEM("testdata/certs/signer.key")
caCert, err := loadCertPEM("testdata/certs/ca.crt")
```

## Regenerate All Certificates

To regenerate all certificates from scratch:

```bash
cd testdata/certs

# Clean up
rm -f *.crt *.key *.csr *.srl *.p12

# Generate CA
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=GoPDF Test CA/CN=GoPDF Test Root CA"

# Generate signer
openssl genrsa -out signer.key 2048
openssl req -new -key signer.key -out signer.csr \
  -subj "/C=DE/ST=Berlin/L=Berlin/O=GoPDF Test/CN=GoPDF Test Signer"
openssl x509 -req -in signer.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out signer.crt -days 365 -sha256

# Create P12 bundle
openssl pkcs12 -export -out signer.p12 -inkey signer.key -in signer.crt \
  -certfile ca.crt -passout pass:test123

# Verify
openssl verify -CAfile ca.crt signer.crt
```
