// Package cli provides command-line interface for PDF signing and verification.
package cli

import (
	"fmt"
	"os"
)

// Version information
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// osExit is a variable for os.Exit to allow testing
var osExit = os.Exit

// Run executes the CLI with the given arguments.
// This is the main entry point for the CLI.
func Run(args []string) {
	if len(args) < 2 {
		Usage()
		return
	}

	command := args[1]

	switch command {
	case "sign":
		SignCommand(args)
	case "verify":
		VerifyCommand(args)
	case "version":
		VersionCommand()
	case "help", "-h", "--help":
		Usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		Usage()
	}
}

// Usage prints the CLI usage information.
func Usage() {
	fmt.Printf("gopdf - PDF signing and verification tool\n\n")
	fmt.Printf("Usage: %s <command> [options] <args>\n\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  sign     Sign a PDF file with a digital signature")
	fmt.Println("  verify   Verify the digital signature(s) of a PDF file")
	fmt.Println("  version  Show version information")
	fmt.Println("  help     Show this help message")
	fmt.Println("")
	fmt.Printf("Use '%s <command> -h' for command-specific help\n", os.Args[0])
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Printf("  %s sign -name \"John Doe\" input.pdf output.pdf cert.pem key.pem\n", os.Args[0])
	fmt.Printf("  %s verify document.pdf\n", os.Args[0])
	fmt.Printf("  %s verify -json document.pdf\n", os.Args[0])
}

// VersionCommand prints version information.
func VersionCommand() {
	fmt.Printf("gopdf version %s\n", Version)
	fmt.Printf("Build time: %s\n", BuildTime)
}
