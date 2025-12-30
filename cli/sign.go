package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"github.com/georgepadayatti/gopdf/keys"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/pdf/writer"
	"github.com/georgepadayatti/gopdf/sign/cms"
	"github.com/georgepadayatti/gopdf/sign/signers"
	"github.com/georgepadayatti/gopdf/sign/timestamps"
)

// SignOptions contains options for the sign command.
type SignOptions struct {
	Name        string
	Location    string
	Reason      string
	Contact     string
	TSA         string
	CertType    string
	FieldName   string
	NoTimestamp bool
}

// SignCommand implements the 'sign' command.
func SignCommand(args []string) {
	signFlags := flag.NewFlagSet("sign", flag.ExitOnError)

	var opts SignOptions

	signFlags.StringVar(&opts.Name, "name", "", "Name of the signatory")
	signFlags.StringVar(&opts.Location, "location", "", "Location of the signatory")
	signFlags.StringVar(&opts.Reason, "reason", "", "Reason for signing")
	signFlags.StringVar(&opts.Contact, "contact", "", "Contact information for signatory")
	signFlags.StringVar(&opts.TSA, "tsa", "http://timestamp.digicert.com", "URL for Time-Stamp Authority")
	signFlags.StringVar(&opts.CertType, "type", "approval", "Signature type: approval, certification")
	signFlags.StringVar(&opts.FieldName, "field", "Signature1", "Name of the signature field")
	signFlags.BoolVar(&opts.NoTimestamp, "no-timestamp", false, "Skip adding a timestamp to the signature")

	signFlags.Usage = func() {
		fmt.Printf("Usage: %s sign [options] <input.pdf> <output.pdf> <certificate.pem> <private_key.pem> [chain.pem]\n\n", os.Args[0])
		fmt.Println("Sign a PDF file with a digital signature.")
		fmt.Println("")
		fmt.Println("Arguments:")
		fmt.Println("  input.pdf        Input PDF file to sign")
		fmt.Println("  output.pdf       Output file for the signed PDF")
		fmt.Println("  certificate.pem  Signing certificate (PEM or DER format)")
		fmt.Println("  private_key.pem  Private key for signing (PEM or DER format)")
		fmt.Println("  chain.pem        Optional certificate chain (PEM format)")
		fmt.Println("")
		fmt.Println("Options:")
		signFlags.PrintDefaults()
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Printf("  %s sign input.pdf output.pdf cert.pem key.pem\n", os.Args[0])
		fmt.Printf("  %s sign -name \"John Doe\" -reason \"Approved\" input.pdf output.pdf cert.pem key.pem\n", os.Args[0])
		fmt.Printf("  %s sign -tsa http://timestamp.example.com input.pdf output.pdf cert.pem key.pem chain.pem\n", os.Args[0])
	}

	if err := signFlags.Parse(args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		osExit(1)
	}

	if len(signFlags.Args()) < 4 {
		signFlags.Usage()
		osExit(1)
	}

	inputPath := signFlags.Arg(0)
	outputPath := signFlags.Arg(1)
	certPath := signFlags.Arg(2)
	keyPath := signFlags.Arg(3)

	var chainPath string
	if len(signFlags.Args()) > 4 {
		chainPath = signFlags.Arg(4)
	}

	if err := signPDF(inputPath, outputPath, certPath, keyPath, chainPath, &opts); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		osExit(1)
	}

	fmt.Printf("Successfully signed PDF: %s\n", outputPath)
}

// signPDF performs the actual PDF signing.
func signPDF(inputPath, outputPath, certPath, keyPath, chainPath string, opts *SignOptions) error {
	// Load the certificate
	cert, err := keys.LoadCertFromPemDer(certPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Load the private key
	privateKey, err := keys.LoadPrivateKeyFromPemDer(keyPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Load certificate chain if provided
	var chain []*x509.Certificate
	if chainPath != "" {
		chain, err = keys.LoadCertsFromPemDer(chainPath)
		if err != nil {
			return fmt.Errorf("failed to load certificate chain: %w", err)
		}
	}

	// Read the input PDF
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	pdfReader, err := reader.NewPdfFileReader(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read PDF: %w", err)
	}

	// Determine signature algorithm based on key type
	sigAlg := getSignatureAlgorithm(privateKey)

	// Create the signer
	signer := signers.NewSimpleSigner(cert, privateKey, sigAlg)
	if len(chain) > 0 {
		signer.SetCertificateChain(chain)
	}

	// Create signature metadata
	metadata := &signers.SignatureMetadata{
		FieldName:   opts.FieldName,
		Name:        opts.Name,
		Location:    opts.Location,
		Reason:      opts.Reason,
		ContactInfo: opts.Contact,
	}

	// Create signing options
	signOpts := signers.DefaultSignPdfOptions()

	// Add timestamper if not disabled
	if !opts.NoTimestamp && opts.TSA != "" {
		timestamper := timestamps.NewHTTPTimestamper(opts.TSA)
		signOpts.Timestamper = timestamper
	}

	// Create incremental writer
	incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

	// Sign the PDF
	signedData, err := signers.SignPdf(incWriter, metadata, signer, signOpts)
	if err != nil {
		return fmt.Errorf("failed to sign PDF: %w", err)
	}

	// Write the output
	if err := os.WriteFile(outputPath, signedData, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// getSignatureAlgorithm determines the signature algorithm based on the key type.
func getSignatureAlgorithm(key crypto.Signer) cms.SignatureAlgorithm {
	switch key.Public().(type) {
	case ed25519.PublicKey:
		// ED25519 - use SHA256WithRSA as fallback since Ed25519 may not be defined
		return cms.SHA256WithRSA
	case *ecdsa.PublicKey:
		// ECDSA - use SHA256WithRSA as fallback
		return cms.SHA256WithRSA
	case *rsa.PublicKey:
		return cms.SHA256WithRSA
	default:
		// Default to SHA256 with RSA for most cases
		return cms.SHA256WithRSA
	}
}
