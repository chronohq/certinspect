# CertInspect

[![go workflow](https://github.com/chronohq/certinspect/actions/workflows/go.yml/badge.svg)](https://github.com/chronohq/certinspect/actions/workflows/go.yml)
[![go reference](https://pkg.go.dev/badge/github.com/chronohq/certinspect.svg)](https://pkg.go.dev/github.com/chronohq/certinspect)
[![mit license](https://img.shields.io/badge/license-MIT-green)](/LICENSE)

**WIP** - This project is in early development.

CertInspect is a Go package for inspecting TLS certificates from remote endpoints, built entirely with Go's standard library for zero external dependencies.
The package includes `certi`, a command-line tool that serves as both a practical utility and reference implementation.

## Features

* Certificate chain inspection
* Expiration time tracking
* Subject and issuer information
* Certificate authority detection

## Command-line Tool

The package includes `certi`, a command-line tool for inspecting certificate chains.

### Installation

**macOS**

```bash
brew install chronohq/tap/certi
```

For other platforms, see the [latest binary release](https://github.com/chronohq/certinspect/releases/latest).

### Basic Usage

```shell
certi --host www.chronohq.com
{
  "hostname": "www.chronohq.com",
  "port": 443,
  "remote_addr": "redacted:443",
  "tls_version": "1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "leaf_expires_at": "redacted",
  "inspected_at": "redacted",
  "chain": [
    {
      "subject": "CN=chronohq.com",
      "issuer": "CN=E8,O=Let's Encrypt,C=US",
      "serial_number": "redacted",
      "version": 3,
      "not_before": "redacted",
      "not_after": "redacted",
      "expires_in": redacted,
      "public_key_algorithm": "ecdsa",
      "signature_algorithm": "ecdsa-sha384",
      "san": [
        {
          "type": "dns",
          "value": "chronohq.com"
        },
        {
          "type": "dns",
          "value": "www.chronohq.com"
        }
      ],
      "is_ca": false
    },
    {
      "subject": "CN=E8,O=Let's Encrypt,C=US",
      "issuer": "CN=ISRG Root X1,O=Internet Security Research Group,C=US",
      "serial_number": "redacted",
      "version": 3,
      "not_before": "redacted",
      "not_after": "redacted",
      "expires_in": redacted,
      "public_key_algorithm": "ecdsa",
      "signature_algorithm": "sha256-rsa",
      "san": [],
      "is_ca": true
    }
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
