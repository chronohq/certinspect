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
	defaultPort = 443
)

var (
	// version holds the application version number.
	// This value is overridden at build time using the -ldflags build flag.
	version = "dev"

	errHostnameRequired = errors.New("hostname is required")
)

type config struct {
	host string
	port int
}

// parseArgs implements GNU-style custom flag parsing to provide --double-dash
// options and position-independent hostname argument, similar to curl and dig.
func parseArgs(args []string) (config, error) {
	cfg := config{port: defaultPort}
	hostArgs := []string{}

	for i := 1; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "--help" || arg == "-h":
			printUsage()
			os.Exit(0)

		case arg == "--version" || arg == "-v":
			fmt.Printf("certi %s\n", version)
			os.Exit(0)

		case strings.HasPrefix(arg, "-"):
			return cfg, fmt.Errorf("unknown option: %s", arg)

		default:
			hostArgs = append(hostArgs, arg)
		}
	}

	if len(hostArgs) == 0 {
		return cfg, errHostnameRequired
	}

	if len(hostArgs) > 1 {
		return cfg, errors.New("only one hostname allowed")
	}

	target := hostArgs[0]

	if len(target) == 0 {
		return cfg, errHostnameRequired
	}

	// use LastIndex to support IPv6.
	idx := strings.LastIndex(target, ":")

	// no port detected, treat as a hostname-only query.
	if idx == -1 {
		cfg.host = target
		return cfg, nil
	}

	// hostname is missing, for example: ":443".
	if idx == 0 {
		return cfg, errHostnameRequired
	}

	cfg.host = target[:idx]
	portStr := target[idx+1:]

	port, err := strconv.Atoi(portStr)

	if err != nil {
		return cfg, errors.New("invalid port number")
	}

	cfg.port = port

	return cfg, nil
}

func printUsage() {
	usage := `certi - TLS certificate chain inspection tool

Usage: certi [OPTIONS] <hostname>[:<port>]

Options:
  --version, -v  Show the version and quit
  --help, -h     Show this help message and quit

Examples:
  certi example.com
  certi 192.168.0.1:3000`

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
