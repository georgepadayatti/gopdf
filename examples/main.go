// Package main provides examples of using the gopdf library for PDF signing and verification.
//
// This demonstrates:
//   - Loading certificates from PEM/PKCS#12 files
//   - Signing PDF documents
//   - Verifying signed PDFs
//   - Certificate chain validation
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/sign/cms"
	"github.com/georgepadayatti/gopdf/sign/signers"
	"software.sslmate.com/src/go-pkcs12"
)

// Paths - works from either project root or examples directory
const (
	caCertFile  = "ca.crt"
	signerCert  = "signer.crt"
	signerKey   = "signer.key"
	signerP12   = "signer.p12"
	p12Password = "test123"
	inputPDF    = "terms.pdf"
	signedPDF   = "terms_signed.pdf"
)

// getTestdataDir finds the testdata directory, works from project root or examples dir
func getTestdataDir() string {
	// Try from project root first
	if _, err := os.Stat("testdata"); err == nil {
		return "testdata"
	}
	// Try from examples directory
	if _, err := os.Stat("../testdata"); err == nil {
		return "../testdata"
	}
	return "testdata"
}

// getCertsDir returns the certificates directory
func getCertsDir() string {
	return filepath.Join(getTestdataDir(), "certs")
}

func main() {
	// Parse command line flags
	action := flag.String("action", "demo", "Action: demo, sign, verify")
	inputFile := flag.String("input", "", "Input PDF file")
	outputFile := flag.String("output", "", "Output signed PDF file")
	certFile := flag.String("cert", "", "Certificate file (PEM or P12)")
	keyFile := flag.String("key", "", "Private key file (PEM)")
	caFile := flag.String("ca", "", "CA certificate file (PEM)")
	password := flag.String("password", "", "Password for P12 file")
	reason := flag.String("reason", "Document approval", "Signature reason")
	location := flag.String("location", "Berlin, Germany", "Signature location")
	visible := flag.Bool("visible", false, "Add visible signature")
	flag.Parse()

	fmt.Println("GoPDF - PDF Signing & Verification Examples")
	fmt.Println("============================================")
	fmt.Println()

	var err error
	switch *action {
	case "demo":
		err = runDemo()
	case "sign":
		err = runSign(*inputFile, *outputFile, *certFile, *keyFile, *password, *reason, *location, *visible)
	case "verify":
		err = runVerify(*inputFile, *caFile)
	default:
		fmt.Printf("Unknown action: %s\n", *action)
		fmt.Println("Available actions: demo, sign, verify")
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// runDemo runs demonstration examples using testdata files.
func runDemo() error {
	fmt.Println("Running demonstration with testdata files...")
	fmt.Println()

	// Example 1: Sign a PDF
	fmt.Println("=== Example 1: Sign PDF ===")
	if err := exampleSignPDF(); err != nil {
		return fmt.Errorf("sign example failed: %w", err)
	}

	fmt.Println()

	// Example 2: Verify a signed PDF
	fmt.Println("=== Example 2: Verify Signed PDF ===")
	if err := exampleVerifyPDF(); err != nil {
		return fmt.Errorf("verify example failed: %w", err)
	}

	fmt.Println()

	// Example 3: Full workflow
	fmt.Println("=== Example 3: Sign and Verify Workflow ===")
	if err := exampleSignAndVerify(); err != nil {
		return fmt.Errorf("sign and verify example failed: %w", err)
	}

	return nil
}

// exampleSignPDF demonstrates signing a PDF with certificates from testdata.
func exampleSignPDF() error {
	certsDir := getCertsDir()
	testdataDir := getTestdataDir()

	// Load signer certificate and key from PKCS#12
	cert, key, caCerts, err := loadP12(filepath.Join(certsDir, signerP12), p12Password)
	if err != nil {
		return fmt.Errorf("failed to load P12: %w", err)
	}

	fmt.Printf("Loaded certificate: %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer: %s\n", cert.Issuer.CommonName)
	fmt.Printf("CA certificates: %d\n", len(caCerts))

	// Load input PDF
	pdfPath := filepath.Join(testdataDir, inputPDF)
	pdfData, err := os.ReadFile(pdfPath)
	if err != nil {
		return fmt.Errorf("failed to read PDF: %w", err)
	}
	fmt.Printf("Input PDF: %s (%d bytes)\n", inputPDF, len(pdfData))

	// Create signer
	signer := signers.NewSimpleSigner(cert, key, cms.SHA256WithRSA)
	signer.SetCertificateChain(caCerts)

	// Create metadata
	metadata := signers.NewSignatureMetadata("Signature1")
	metadata.Reason = "Document approval"
	metadata.Location = "Berlin, Germany"
	metadata.Name = cert.Subject.CommonName

	// Sign PDF
	signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, nil)
	if err != nil {
		return fmt.Errorf("failed to sign PDF: %w", err)
	}

	fmt.Printf("Signed PDF: %d bytes\n", len(signedData))

	// Save signed PDF
	outputPath := filepath.Join(getTestdataDir(), "demo_signed.pdf")
	if err := os.WriteFile(outputPath, signedData, 0644); err != nil {
		return fmt.Errorf("failed to write signed PDF: %w", err)
	}
	fmt.Printf("Saved to: %s\n", outputPath)

	return nil
}

// exampleVerifyPDF demonstrates verifying a signed PDF.
func exampleVerifyPDF() error {
	certsDir := getCertsDir()
	testdataDir := getTestdataDir()

	// Load CA certificate for verification
	caCert, err := loadCertPEM(filepath.Join(certsDir, caCertFile))
	if err != nil {
		return fmt.Errorf("failed to load CA cert: %w", err)
	}
	fmt.Printf("Loaded CA: %s\n", caCert.Subject.CommonName)

	// Load signed PDF
	pdfPath := filepath.Join(testdataDir, "demo_signed.pdf")
	pdfData, err := os.ReadFile(pdfPath)
	if err != nil {
		// Try the pre-existing signed PDF
		pdfPath = filepath.Join(testdataDir, signedPDF)
		pdfData, err = os.ReadFile(pdfPath)
		if err != nil {
			return fmt.Errorf("failed to read signed PDF: %w", err)
		}
	}
	fmt.Printf("Verifying: %s (%d bytes)\n", filepath.Base(pdfPath), len(pdfData))

	// Verify signatures
	results, err := VerifyPDFSignatures(pdfData, []*x509.Certificate{caCert})
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Print results
	fmt.Printf("\nSignature verification results:\n")
	for i, result := range results {
		fmt.Printf("\n  Signature %d:\n", i+1)
		fmt.Printf("    Field: %s\n", result.FieldName)
		fmt.Printf("    Signer: %s\n", result.SignerName)
		fmt.Printf("    Reason: %s\n", result.Reason)
		fmt.Printf("    Location: %s\n", result.Location)
		fmt.Printf("    Integrity: %s\n", boolToStatus(result.IntegrityValid))
		fmt.Printf("    Certificate: %s\n", boolToStatus(result.CertificateValid))
		if result.Error != "" {
			fmt.Printf("    Error: %s\n", result.Error)
		}
	}

	return nil
}

// exampleSignAndVerify demonstrates a complete sign-then-verify workflow.
func exampleSignAndVerify() error {
	certsDir := getCertsDir()
	testdataDir := getTestdataDir()

	// Load certificates
	cert, key, caCerts, err := loadP12(filepath.Join(certsDir, signerP12), p12Password)
	if err != nil {
		return fmt.Errorf("failed to load P12: %w", err)
	}

	caCert, err := loadCertPEM(filepath.Join(certsDir, caCertFile))
	if err != nil {
		return fmt.Errorf("failed to load CA cert: %w", err)
	}

	// Load input PDF
	pdfPath := filepath.Join(testdataDir, inputPDF)
	pdfData, err := os.ReadFile(pdfPath)
	if err != nil {
		return fmt.Errorf("failed to read PDF: %w", err)
	}
	fmt.Printf("Input: %s (%d bytes)\n", inputPDF, len(pdfData))

	// Sign
	signer := signers.NewSimpleSigner(cert, key, cms.SHA256WithRSA)
	signer.SetCertificateChain(caCerts)

	metadata := signers.NewSignatureMetadata("WorkflowSig")
	metadata.Reason = "Workflow test"
	metadata.Location = "Test Lab"
	metadata.Name = cert.Subject.CommonName

	signedData, err := signers.SignPdfBytes(pdfData, metadata, signer, nil)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	fmt.Printf("Signed: %d bytes\n", len(signedData))

	// Verify
	results, err := VerifyPDFSignatures(signedData, []*x509.Certificate{caCert})
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Check results
	allValid := true
	for _, result := range results {
		if !result.IntegrityValid || !result.CertificateValid {
			allValid = false
		}
	}

	if allValid {
		fmt.Println("All signatures verified successfully!")
	} else {
		fmt.Println("WARNING: Some signatures failed verification")
	}

	return nil
}

// runSign signs a PDF file.
func runSign(input, output, certFile, keyFile, password, reason, location string, visible bool) error {
	if input == "" {
		return fmt.Errorf("input file required (-input)")
	}

	// Determine certificate source
	var cert *x509.Certificate
	var key crypto.Signer
	var chain []*x509.Certificate

	if certFile != "" && filepath.Ext(certFile) == ".p12" {
		// Load from PKCS#12
		if password == "" {
			return fmt.Errorf("password required for P12 file (-password)")
		}
		var err error
		cert, key, chain, err = loadP12(certFile, password)
		if err != nil {
			return fmt.Errorf("failed to load P12: %w", err)
		}
	} else if certFile != "" && keyFile != "" {
		// Load from PEM files
		var err error
		cert, err = loadCertPEM(certFile)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		key, err = loadKeyPEM(keyFile)
		if err != nil {
			return fmt.Errorf("failed to load key: %w", err)
		}
	} else {
		return fmt.Errorf("certificate required (-cert with -key for PEM, or -cert with -password for P12)")
	}

	fmt.Printf("Certificate: %s\n", cert.Subject.CommonName)

	// Load PDF
	pdfData, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	fmt.Printf("Input: %s (%d bytes)\n", input, len(pdfData))

	// Parse PDF
	pdfReader, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		return fmt.Errorf("failed to parse PDF: %w", err)
	}

	// Create signer
	signer := signers.NewSimpleSigner(cert, key, cms.SHA256WithRSA)
	signer.SetCertificateChain(chain)

	// Create metadata
	metadata := signers.NewSignatureMetadata("Signature1")
	metadata.Reason = reason
	metadata.Location = location
	metadata.Name = cert.Subject.CommonName

	// Create PDF signer
	pdfSigner := signers.NewPdfSigner(signer, metadata)

	// Add visible signature if requested
	if visible {
		rect := &generic.Rectangle{LLX: 50, LLY: 50, URX: 250, URY: 100}
		pdfSigner.SetSignatureAppearance(0, rect)
	}

	// Sign
	signedData, err := pdfSigner.SignPdf(pdfReader)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	fmt.Printf("Signed: %d bytes\n", len(signedData))

	// Determine output path
	if output == "" {
		ext := filepath.Ext(input)
		base := input[:len(input)-len(ext)]
		output = base + "_signed" + ext
	}

	// Save
	if err := os.WriteFile(output, signedData, 0644); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	fmt.Printf("Output: %s\n", output)

	return nil
}

// runVerify verifies signatures in a PDF file.
func runVerify(input, caFile string) error {
	if input == "" {
		return fmt.Errorf("input file required (-input)")
	}

	// Load PDF
	pdfData, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	fmt.Printf("Verifying: %s (%d bytes)\n", input, len(pdfData))

	// Load CA certificates if provided
	var caCerts []*x509.Certificate
	if caFile != "" {
		caCert, err := loadCertPEM(caFile)
		if err != nil {
			return fmt.Errorf("failed to load CA cert: %w", err)
		}
		caCerts = []*x509.Certificate{caCert}
		fmt.Printf("CA: %s\n", caCert.Subject.CommonName)
	}

	// Verify
	results, err := VerifyPDFSignatures(pdfData, caCerts)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Print results
	fmt.Printf("\nFound %d signature(s):\n", len(results))
	allValid := true
	for i, result := range results {
		fmt.Printf("\n  Signature %d:\n", i+1)
		fmt.Printf("    Field: %s\n", result.FieldName)
		fmt.Printf("    Signer: %s\n", result.SignerName)
		fmt.Printf("    Reason: %s\n", result.Reason)
		fmt.Printf("    Location: %s\n", result.Location)
		fmt.Printf("    Signing Time: %s\n", result.SigningTime)
		fmt.Printf("    Integrity: %s\n", boolToStatus(result.IntegrityValid))
		fmt.Printf("    Certificate: %s\n", boolToStatus(result.CertificateValid))
		if result.Error != "" {
			fmt.Printf("    Error: %s\n", result.Error)
			allValid = false
		}
		if !result.IntegrityValid || !result.CertificateValid {
			allValid = false
		}
	}

	fmt.Println()
	if allValid && len(results) > 0 {
		fmt.Println("All signatures are VALID")
	} else if len(results) == 0 {
		fmt.Println("No signatures found in document")
	} else {
		fmt.Println("WARNING: Some signatures are INVALID")
	}

	return nil
}

// SignatureVerificationResult contains the result of verifying a signature.
type SignatureVerificationResult struct {
	FieldName        string
	SignerName       string
	Reason           string
	Location         string
	SigningTime      string
	IntegrityValid   bool
	CertificateValid bool
	Error            string
}

// VerifyPDFSignatures verifies all signatures in a PDF document.
func VerifyPDFSignatures(pdfData []byte, trustedCAs []*x509.Certificate) ([]SignatureVerificationResult, error) {
	// Parse PDF
	pdfReader, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PDF: %w", err)
	}

	// Get embedded signatures using the proper API
	embeddedSigs, err := pdfReader.GetEmbeddedSignatures()
	if err != nil {
		return nil, fmt.Errorf("failed to get embedded signatures: %w", err)
	}

	var results []SignatureVerificationResult

	for _, sig := range embeddedSigs {
		result := SignatureVerificationResult{}

		// Get field name
		if nameObj := sig.Field.Get("T"); nameObj != nil {
			if str, ok := nameObj.(*generic.StringObject); ok {
				result.FieldName = str.Text()
			}
		}

		// Get signature metadata from dictionary
		if reasonObj := sig.Dictionary.Get("Reason"); reasonObj != nil {
			if str, ok := reasonObj.(*generic.StringObject); ok {
				result.Reason = str.Text()
			}
		}

		if locObj := sig.Dictionary.Get("Location"); locObj != nil {
			if str, ok := locObj.(*generic.StringObject); ok {
				result.Location = str.Text()
			}
		}

		if nameObj := sig.Dictionary.Get("Name"); nameObj != nil {
			if str, ok := nameObj.(*generic.StringObject); ok {
				result.SignerName = str.Text()
			}
		}

		result.SigningTime = sig.GetSigningTime()

		// Get signature contents and signed data
		// PDF Contents field is padded with zeros - trim them
		signatureBytes := trimTrailingZeros(sig.Contents)
		if len(signatureBytes) == 0 {
			result.Error = "no signature contents"
			results = append(results, result)
			continue
		}

		signedData := sig.GetSignedData()
		if len(signedData) == 0 {
			result.Error = "no signed data"
			results = append(results, result)
			continue
		}

		// Verify CMS signature
		integrityValid, certValid, signerName, verifyErr := verifyCMSSignature(signatureBytes, signedData, trustedCAs)
		result.IntegrityValid = integrityValid
		result.CertificateValid = certValid
		if signerName != "" && result.SignerName == "" {
			result.SignerName = signerName
		}
		if verifyErr != nil {
			result.Error = verifyErr.Error()
		}

		results = append(results, result)
	}

	return results, nil
}

// verifyCMSSignature verifies a CMS signature.
func verifyCMSSignature(signature, data []byte, trustedCAs []*x509.Certificate) (integrityValid, certValid bool, signerName string, err error) {
	// Get signer certificates from CMS
	certs, err := cms.GetSignerCertificates(signature)
	if err != nil {
		return false, false, "", fmt.Errorf("failed to get signer certificates: %w", err)
	}

	var signerCert *x509.Certificate
	if len(certs) > 0 {
		signerCert = certs[0]
		signerName = signerCert.Subject.CommonName
	}

	// Verify signature integrity
	err = cms.VerifyCMSSignature(signature, data)
	if err != nil {
		return false, false, signerName, fmt.Errorf("signature verification failed: %w", err)
	}
	integrityValid = true

	// Verify certificate chain if CA certs provided
	if len(trustedCAs) > 0 && signerCert != nil {
		roots := x509.NewCertPool()
		for _, ca := range trustedCAs {
			roots.AddCert(ca)
		}

		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		_, err = signerCert.Verify(opts)
		if err != nil {
			return integrityValid, false, signerName, fmt.Errorf("certificate verification failed: %w", err)
		}
		certValid = true
	} else {
		// No CA provided, skip certificate chain validation
		certValid = true
	}

	return integrityValid, certValid, signerName, nil
}

// loadP12 loads a certificate and key from a PKCS#12 file.
func loadP12(path, password string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	key, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode P12: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, nil, fmt.Errorf("key is not a signer")
	}

	return cert, signer, caCerts, nil
}

// loadCertPEM loads a certificate from a PEM file.
func loadCertPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// loadKeyPEM loads a private key from a PEM file.
func loadKeyPEM(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	// Try parsing as PKCS#8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}

	// Try parsing as PKCS#1 RSA key
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return rsaKey, nil
	}

	// Try parsing as EC key
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return ecKey, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// trimTrailingZeros removes trailing zero bytes from PDF signature contents.
// PDF reserves space for signatures by padding with zeros.
func trimTrailingZeros(data []byte) []byte {
	end := len(data)
	for end > 0 && data[end-1] == 0 {
		end--
	}
	return data[:end]
}

// boolToStatus converts a boolean to a status string.
func boolToStatus(b bool) string {
	if b {
		return "VALID"
	}
	return "INVALID"
}
