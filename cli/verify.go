package cli

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/georgepadayatti/gopdf/keys"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/sign/validation"
)

// VerifyOptions contains options for the verify command.
type VerifyOptions struct {
	EnableExternalRevocation bool
	TrustSignatureTime       bool
	ValidateTimestampCerts   bool
	AllowEmbeddedRoots       bool
	HTTPTimeout              time.Duration
	TrustRootsFile           string
	JSON                     bool
	Verbose                  bool
}

// VerifyCommand implements the 'verify' command.
func VerifyCommand(args []string) {
	verifyFlags := flag.NewFlagSet("verify", flag.ExitOnError)

	var opts VerifyOptions

	verifyFlags.BoolVar(&opts.EnableExternalRevocation, "external", false, "Enable external OCSP and CRL checking")
	verifyFlags.BoolVar(&opts.TrustSignatureTime, "trust-signature-time", false, "Trust the signature time if no timestamp is present (insecure)")
	verifyFlags.BoolVar(&opts.ValidateTimestampCerts, "validate-timestamp-certs", true, "Validate timestamp token certificates")
	verifyFlags.BoolVar(&opts.AllowEmbeddedRoots, "allow-embedded-roots", false, "Allow certificates embedded in the PDF to be used as trusted roots (insecure)")
	verifyFlags.DurationVar(&opts.HTTPTimeout, "http-timeout", 10*time.Second, "Timeout for external revocation checking requests")
	verifyFlags.StringVar(&opts.TrustRootsFile, "trust-roots", "", "File containing trusted root certificates (PEM format)")
	verifyFlags.BoolVar(&opts.JSON, "json", false, "Output results in JSON format")
	verifyFlags.BoolVar(&opts.Verbose, "verbose", false, "Show detailed validation information")

	verifyFlags.Usage = func() {
		fmt.Printf("Usage: %s verify [options] <input.pdf>\n\n", os.Args[0])
		fmt.Println("Verify the digital signature(s) of a PDF file.")
		fmt.Println("")
		fmt.Println("Arguments:")
		fmt.Println("  input.pdf  PDF file to verify")
		fmt.Println("")
		fmt.Println("Options:")
		verifyFlags.PrintDefaults()
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Printf("  %s verify document.pdf\n", os.Args[0])
		fmt.Printf("  %s verify -json document.pdf\n", os.Args[0])
		fmt.Printf("  %s verify -external -http-timeout=30s document.pdf\n", os.Args[0])
		fmt.Printf("  %s verify -trust-roots trusted-cas.pem document.pdf\n", os.Args[0])
	}

	if err := verifyFlags.Parse(args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		osExit(1)
	}

	if len(verifyFlags.Args()) < 1 {
		verifyFlags.Usage()
		osExit(1)
	}

	inputPath := verifyFlags.Arg(0)

	output, err := verifyPDF(inputPath, &opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		osExit(1)
	}

	// Output results
	if opts.JSON {
		outputJSON(output)
	} else {
		outputText(output, opts.Verbose)
	}

	// Exit with non-zero code if any signature is invalid
	for _, result := range output.Signatures {
		if result.Status == "INVALID" {
			osExit(1)
		}
	}
}

// VerifyOutput is the complete verification output including document info and signatures.
type VerifyOutput struct {
	Document   *DocumentInfoJSON `json:"document,omitempty"`
	Signatures []*VerifyResult   `json:"signatures"`
}

// VerifyResult is a JSON-serializable verification result for a single signature.
type VerifyResult struct {
	SignatureIndex int              `json:"signature_index"`
	FieldName      string           `json:"field_name,omitempty"`
	Status         string           `json:"status"`
	IntegrityValid bool             `json:"integrity_valid"`
	TrustValid     bool             `json:"trust_valid"`
	SignerName     string           `json:"signer_name,omitempty"`
	SigningTime    string           `json:"signing_time,omitempty"`
	TimestampTime  string           `json:"timestamp_time,omitempty"`
	TimeSource     string           `json:"time_source,omitempty"`
	Reason         string           `json:"reason,omitempty"`
	Location       string           `json:"location,omitempty"`
	SubFilter      string           `json:"sub_filter,omitempty"`
	Errors         []string         `json:"errors,omitempty"`
	Warnings       []string         `json:"warnings,omitempty"`
	Certificate    *CertificateInfo `json:"certificate,omitempty"`
	Revocation     *RevocationInfo  `json:"revocation,omitempty"`
	KeyUsage       *KeyUsageInfo    `json:"key_usage,omitempty"`
}

// DocumentInfoJSON contains PDF document metadata for JSON output.
type DocumentInfoJSON struct {
	Title        string   `json:"title,omitempty"`
	Author       string   `json:"author,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Keywords     []string `json:"keywords,omitempty"`
	Creator      string   `json:"creator,omitempty"`
	Producer     string   `json:"producer,omitempty"`
	CreationDate string   `json:"creation_date,omitempty"`
	ModDate      string   `json:"mod_date,omitempty"`
	Pages        int      `json:"pages"`
	Trapped      string   `json:"trapped,omitempty"`
}

// CertificateInfo contains certificate information for JSON output.
type CertificateInfo struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Serial     string `json:"serial"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	IsExpired  bool   `json:"is_expired"`
}

// RevocationInfo contains revocation information for JSON output.
type RevocationInfo struct {
	Status               string `json:"status"`
	RevokedBeforeSigning bool   `json:"revoked_before_signing,omitempty"`
	RevocationTime       string `json:"revocation_time,omitempty"`
	RevocationReason     string `json:"revocation_reason,omitempty"`
	RevocationSource     string `json:"revocation_source,omitempty"`
	CanDetermineTiming   bool   `json:"can_determine_timing"`
}

// KeyUsageInfo contains key usage information for JSON output.
type KeyUsageInfo struct {
	HasDigitalSignature   bool     `json:"has_digital_signature"`
	HasNonRepudiation     bool     `json:"has_non_repudiation"`
	HasDocumentSigningEKU bool     `json:"has_document_signing_eku"`
	ExtKeyUsages          []string `json:"ext_key_usages,omitempty"`
}

// verifyPDF performs the actual PDF verification.
func verifyPDF(inputPath string, opts *VerifyOptions) (*VerifyOutput, error) {
	// Open the input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	// Read the PDF
	pdfReader, err := reader.NewPdfFileReader(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read PDF: %w", err)
	}

	// Extract document info
	docInfo := validation.ExtractDocumentInfo(pdfReader)
	var docInfoJSON *DocumentInfoJSON
	if docInfo != nil {
		docInfoJSON = &DocumentInfoJSON{
			Title:    docInfo.Title,
			Author:   docInfo.Author,
			Subject:  docInfo.Subject,
			Keywords: docInfo.Keywords,
			Creator:  docInfo.Creator,
			Producer: docInfo.Producer,
			Pages:    docInfo.Pages,
			Trapped:  docInfo.Trapped,
		}
		if docInfo.CreationDate != nil {
			docInfoJSON.CreationDate = docInfo.CreationDate.Format(time.RFC3339)
		}
		if docInfo.ModDate != nil {
			docInfoJSON.ModDate = docInfo.ModDate.Format(time.RFC3339)
		}
	}

	// Create validator settings
	settings := validation.DefaultValidatorSettings()
	settings.TrustSignatureTime = opts.TrustSignatureTime
	settings.ValidateTimestampCertificates = opts.ValidateTimestampCerts
	settings.AllowEmbeddedRoots = opts.AllowEmbeddedRoots
	settings.EnableExternalRevocationCheck = opts.EnableExternalRevocation
	settings.HTTPTimeout = opts.HTTPTimeout

	// Load trusted roots if specified
	if opts.TrustRootsFile != "" {
		roots, err := keys.LoadCertsFromPemDer(opts.TrustRootsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load trusted roots: %w", err)
		}
		rootPool := x509.NewCertPool()
		for _, root := range roots {
			rootPool.AddCert(root)
		}
		settings.TrustRoots = rootPool
	}

	// Create the validator
	validator := validation.NewSignatureValidator(settings)

	// Validate all signatures
	validationResults, err := validator.ValidateSignatures(pdfReader)
	if err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Convert to JSON-serializable results
	var results []*VerifyResult
	for i, vr := range validationResults {
		result := &VerifyResult{
			SignatureIndex: i + 1,
			Status:         vr.Status.String(),
			IntegrityValid: vr.IntegrityStatus == validation.StatusValid,
			TrustValid:     vr.TrustStatus == validation.StatusValid,
			SubFilter:      vr.SubFilter,
			Reason:         vr.Reason,
			Location:       vr.Location,
			FieldName:      vr.Name,
		}

		// Add signing time
		if !vr.SigningTime.IsZero() {
			result.SigningTime = vr.SigningTime.Format(time.RFC3339)
		}

		// Add timestamp time
		if !vr.TimestampTime.IsZero() {
			result.TimestampTime = vr.TimestampTime.Format(time.RFC3339)
		}

		// Add time source info
		if vr.TimeResult != nil {
			result.TimeSource = string(vr.TimeResult.TimeSource)
			result.Warnings = append(result.Warnings, vr.TimeResult.TimeWarnings...)
		}

		// Add certificate info
		if vr.SignerCertificate != nil {
			result.SignerName = vr.SignerCertificate.Subject.CommonName
			result.Certificate = &CertificateInfo{
				Subject:   vr.SignerCertificate.Subject.String(),
				Issuer:    vr.SignerCertificate.Issuer.String(),
				Serial:    vr.SignerCertificate.SerialNumber.String(),
				NotBefore: vr.SignerCertificate.NotBefore.Format(time.RFC3339),
				NotAfter:  vr.SignerCertificate.NotAfter.Format(time.RFC3339),
				IsExpired: time.Now().After(vr.SignerCertificate.NotAfter),
			}
		}

		// Add key usage info
		if vr.KeyUsageResult != nil {
			result.KeyUsage = &KeyUsageInfo{
				HasDigitalSignature:   vr.KeyUsageResult.HasDigitalSignature,
				HasNonRepudiation:     vr.KeyUsageResult.HasNonRepudiation,
				HasDocumentSigningEKU: vr.KeyUsageResult.HasDocumentSigningEKU,
			}
			for _, eku := range vr.KeyUsageResult.ExtKeyUsages {
				result.KeyUsage.ExtKeyUsages = append(result.KeyUsage.ExtKeyUsages, string(eku))
			}
		}

		// Add revocation info
		if vr.RevocationResult != nil {
			result.Revocation = &RevocationInfo{
				Status:               string(vr.RevocationResult.Status),
				RevokedBeforeSigning: vr.RevocationResult.RevokedBeforeSigning,
				CanDetermineTiming:   vr.RevocationResult.CanDetermineTiming,
			}
			if vr.RevocationResult.RevocationTime != nil {
				result.Revocation.RevocationTime = vr.RevocationResult.RevocationTime.Format(time.RFC3339)
			}
			result.Revocation.RevocationReason = vr.RevocationResult.RevocationReason
			result.Revocation.RevocationSource = vr.RevocationResult.RevocationSource
			result.Warnings = append(result.Warnings, vr.RevocationResult.Warnings...)
		}

		// Add errors
		for _, e := range vr.Errors {
			result.Errors = append(result.Errors, e.Error())
		}

		// Add other warnings
		result.Warnings = append(result.Warnings, vr.Warnings...)

		results = append(results, result)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no signatures found in the PDF")
	}

	return &VerifyOutput{
		Document:   docInfoJSON,
		Signatures: results,
	}, nil
}

// outputJSON outputs the results in JSON format.
func outputJSON(output *VerifyOutput) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		osExit(1)
	}
}

// outputText outputs the results in human-readable text format.
func outputText(output *VerifyOutput, verbose bool) {
	fmt.Printf("PDF Verification Results\n")
	fmt.Printf("========================\n\n")

	// Print document info if available
	if output.Document != nil && verbose {
		fmt.Printf("Document Information\n")
		fmt.Printf("--------------------\n")
		if output.Document.Title != "" {
			fmt.Printf("  Title: %s\n", output.Document.Title)
		}
		if output.Document.Author != "" {
			fmt.Printf("  Author: %s\n", output.Document.Author)
		}
		if output.Document.Subject != "" {
			fmt.Printf("  Subject: %s\n", output.Document.Subject)
		}
		if output.Document.Creator != "" {
			fmt.Printf("  Creator: %s\n", output.Document.Creator)
		}
		if output.Document.Producer != "" {
			fmt.Printf("  Producer: %s\n", output.Document.Producer)
		}
		if output.Document.CreationDate != "" {
			fmt.Printf("  Created: %s\n", output.Document.CreationDate)
		}
		if output.Document.ModDate != "" {
			fmt.Printf("  Modified: %s\n", output.Document.ModDate)
		}
		fmt.Printf("  Pages: %d\n", output.Document.Pages)
		if len(output.Document.Keywords) > 0 {
			fmt.Printf("  Keywords: %v\n", output.Document.Keywords)
		}
		fmt.Println()
	}

	fmt.Printf("Found %d signature(s)\n\n", len(output.Signatures))

	for _, result := range output.Signatures {
		fmt.Printf("Signature #%d\n", result.SignatureIndex)
		fmt.Printf("------------\n")

		// Status with color indication
		statusIcon := getStatusIcon(result.Status)
		fmt.Printf("  Status: %s %s\n", statusIcon, result.Status)

		if result.FieldName != "" {
			fmt.Printf("  Field: %s\n", result.FieldName)
		}

		fmt.Printf("  Integrity: %s\n", boolToStatus(result.IntegrityValid))
		fmt.Printf("  Trust: %s\n", boolToStatus(result.TrustValid))

		if result.SignerName != "" {
			fmt.Printf("  Signer: %s\n", result.SignerName)
		}

		if result.SigningTime != "" {
			fmt.Printf("  Signing Time: %s\n", result.SigningTime)
		}

		if result.TimestampTime != "" {
			fmt.Printf("  Timestamp: %s\n", result.TimestampTime)
		}

		if result.TimeSource != "" {
			fmt.Printf("  Time Source: %s\n", result.TimeSource)
		}

		if result.Reason != "" {
			fmt.Printf("  Reason: %s\n", result.Reason)
		}

		if result.Location != "" {
			fmt.Printf("  Location: %s\n", result.Location)
		}

		// Verbose output
		if verbose {
			if result.Certificate != nil {
				fmt.Printf("\n  Certificate Details:\n")
				fmt.Printf("    Subject: %s\n", result.Certificate.Subject)
				fmt.Printf("    Issuer: %s\n", result.Certificate.Issuer)
				fmt.Printf("    Serial: %s\n", result.Certificate.Serial)
				fmt.Printf("    Valid: %s to %s\n", result.Certificate.NotBefore, result.Certificate.NotAfter)
				if result.Certificate.IsExpired {
					fmt.Printf("    WARNING: Certificate is expired!\n")
				}
			}

			if result.KeyUsage != nil {
				fmt.Printf("\n  Key Usage:\n")
				fmt.Printf("    Digital Signature: %v\n", result.KeyUsage.HasDigitalSignature)
				fmt.Printf("    Non-Repudiation: %v\n", result.KeyUsage.HasNonRepudiation)
				fmt.Printf("    Document Signing EKU: %v\n", result.KeyUsage.HasDocumentSigningEKU)
				if len(result.KeyUsage.ExtKeyUsages) > 0 {
					fmt.Printf("    Extended Key Usages: %v\n", result.KeyUsage.ExtKeyUsages)
				}
			}

			if result.Revocation != nil {
				fmt.Printf("\n  Revocation Status:\n")
				fmt.Printf("    Status: %s\n", result.Revocation.Status)
				if result.Revocation.RevokedBeforeSigning {
					fmt.Printf("    WARNING: Certificate was revoked BEFORE signing!\n")
				}
			}
		}

		// Errors
		if len(result.Errors) > 0 {
			fmt.Printf("\n  Errors:\n")
			for _, e := range result.Errors {
				fmt.Printf("    - %s\n", e)
			}
		}

		// Warnings
		if len(result.Warnings) > 0 {
			fmt.Printf("\n  Warnings:\n")
			for _, w := range result.Warnings {
				fmt.Printf("    - %s\n", w)
			}
		}

		fmt.Println()
	}
}

// getStatusIcon returns an icon for the status.
func getStatusIcon(status string) string {
	switch status {
	case "VALID":
		return "[OK]"
	case "INVALID":
		return "[FAIL]"
	case "WARNING":
		return "[WARN]"
	default:
		return "[?]"
	}
}

// boolToStatus converts a boolean to a status string.
func boolToStatus(b bool) string {
	if b {
		return "OK"
	}
	return "FAILED"
}
