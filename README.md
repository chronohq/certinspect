# CertInspect

[![go workflow](https://github.com/chronohq/certinspect/actions/workflows/go.yml/badge.svg)](https://github.com/chronohq/certinspect/actions/workflows/go.yml)
[![go reference](https://pkg.go.dev/badge/github.com/chronohq/certinspect.svg)](https://pkg.go.dev/github.com/chronohq/certinspect)
[![mit license](https://img.shields.io/badge/license-MIT-green)](/LICENSE)

**WIP** - This project is in early development.

CertInspect is a Go package for inspecting TLS certificates from remote endpoints, built entirely with Go's standard library for zero external dependencies.
The package includes `certi`, a command-line tool that serves as both a practical utility and reference implementation.

## Features

* Programmatic certificate chain inspection API
* CLI tool included for manual certificate chain inspection
* Certificate expiration time tracking
* Subject Alternative Name (SAN) parsing
* IPv6 address support
* Zero external dependencies

## Command-line Tool

The package includes `certi`, a command-line tool for inspecting certificate chains.

### Installation

**macOS**

```bash
brew install chronohq/tap/certi
```

For other platforms, see the [latest binary release](https://github.com/chronohq/certinspect/releases/latest).

### Basic Usage

Inspect a certificate on the default HTTPS port (443):

```shell
certi www.chronohq.com
{
  ...
  "chain": [
    ...
  ]
}
```

Inspect a certificate on a custom port:

```shell
certi www.chronohq.com:3000
{
  ...
  "chain": [
    ...
  ]
}
```

## Design Philosophy

CertInspect is a single-purpose component designed for certificate inspection and analysis.
At [Chrono](https://www.chronohq.com/), we use it as part of our larger monitoring infrastructure.

The package uses only Go's standard library to ensure zero external dependencies, maximum compatibility, and reduced supply chain risk.
This is particularly important for a component handling TLS certificate data.

## License

CertInspect is available under the [MIT license](https://opensource.org/license/MIT).
See the [LICENSE](LICENSE) file for details.
