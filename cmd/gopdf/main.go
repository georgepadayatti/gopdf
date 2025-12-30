// Command gopdf is a CLI tool for PDF signing and verification.
//
// Usage:
//
//	gopdf <command> [options] <args>
//
// Commands:
//
//	sign     Sign a PDF file with a digital signature
//	verify   Verify the digital signature(s) of a PDF file
//	version  Show version information
//	help     Show help message
//
// Examples:
//
//	# Sign a PDF
//	gopdf sign -name "John Doe" input.pdf output.pdf cert.pem key.pem
//
//	# Verify a PDF
//	gopdf verify document.pdf
//
//	# Verify with JSON output
//	gopdf verify -json document.pdf
package main

import (
	"os"

	"github.com/georgepadayatti/gopdf/cli"
)

// These variables are set at build time using ldflags:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/gopdf
var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Set version info
	cli.Version = version
	cli.BuildTime = buildTime

	// Run the CLI
	cli.Run(os.Args)
}
