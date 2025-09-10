// Copyright Chrono Technologies LLC
// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/chronohq/certinspect"
)

const (
	defaultPort     = 443
	errHostRequired = "--host requires a value"
	errPortRequired = "--port requires a value"
	errPortInvalid  = "invalid port value"
)

var (
	// version holds the application version number.
	// This value is overridden at build time using the -ldflags build flag.
	version = "dev"
)

type config struct {
	host string
	port int
}

// parseArgs implements GNU-style flag parsing to provide familiar
// --double-dash option syntax without external dependencies.
func parseArgs(args []string) (config, error) {
	cfg := config{port: defaultPort}

	for i := range args {
		// skip program name
		if i == 0 {
			continue
		}

		arg := args[i]

		switch {
		case arg == "--host":
			if i+1 >= len(args) {
				return cfg, errors.New(errHostRequired)
			}

			val := args[i+1]

			if len(val) == 0 {
				return cfg, errors.New(errHostRequired)
			}

			cfg.host = val
			i++ // skip the value token

		case strings.HasPrefix(arg, "--host="):
			val := strings.SplitN(arg, "=", 2)[1]

			if len(val) == 0 {
				return cfg, errors.New(errHostRequired)
			}

			cfg.host = val

		case arg == "--port":
			if i+1 >= len(args) {
				return cfg, errors.New(errPortRequired)
			}

			val := args[i+1]

			if len(val) == 0 {
				return cfg, errors.New(errPortRequired)
			}

			port, err := strconv.Atoi(val)

			if err != nil {
				return cfg, errors.New(errPortInvalid)
			}

			cfg.port = port
			i++ // skip the value token

		case strings.HasPrefix(arg, "--port="):
			val := strings.SplitN(arg, "=", 2)[1]

			if len(val) == 0 {
				return cfg, errors.New(errPortRequired)
			}

			port, err := strconv.Atoi(val)

			if err != nil {
				return cfg, errors.New(errPortInvalid)
			}

			cfg.port = port

		case arg == "--help" || arg == "-h":
			printUsage()
			os.Exit(0)

		case arg == "--version" || arg == "-v":
			fmt.Printf("certi %s\n", version)
			os.Exit(0)
		}
	}

	if len(cfg.host) == 0 {
		return cfg, errors.New("--host is required")
	}

	return cfg, nil
}

func printUsage() {
	usage := `certi - TLS certificate chain inspection tool

Usage: certi [OPTIONS]

Options:
  --host host    Server host (required)
  --port port    Server port (default: 443)
  --version, -v  Show the version and quit
  --help, -h     Show this help message and quit

Examples:
  certi --host example.com
  certi --host 192.168.1.100 --port 3000`

	fmt.Fprintln(os.Stderr, usage)
}

func main() {
	cfg, err := parseArgs(os.Args)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var res certinspect.Result
	var output []byte

	inspector := certinspect.New()

	if res, err = inspector.Inspect(cfg.host, cfg.port); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if output, err = json.MarshalIndent(res, "", "  "); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
