// Copyright Chrono Technologies LLC
// SPDX-License-Identifier: MIT
//
// Package certinspect provides TLS certificate inspection for remote endpoints.
package certinspect

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout = 10 * time.Second
	maxPort        = 1<<16 - 1
)

type Inspector struct {
	timeout time.Duration
}

// Certificate represents an X.509 certificate with its properties and metadata.
type Certificate struct {
	// Subject is the entity this certificate was issued to.
	Subject string `json:"subject"`

	// Issuer is the entity that signed this certificate.
	Issuer string `json:"issuer"`

	// SerialNumber is the unique identifier assigned by the issuer.
	SerialNumber string `json:"serial_number"`

	// Version is the X.509 certificate format version.
	Version int `json:"version"`

	// NotBefore is when this certificate becomes valid.
	NotBefore time.Time `json:"not_before"`

	// NotAfter is when this certificate expires.
	NotAfter time.Time `json:"not_after"`

	// ExpiresIn is the time remaining until certificate expiration or negative
	// if already expired.
	ExpiresIn time.Duration `json:"expires_in"`

	// PublicKeyAlgorithm is the algorithm used to generate the public key.
	PublicKeyAlgorithm string `json:"public_key_algorithm"`

	// SignatureAlgorithm is the algorithm used to sign this certificate.
	SignatureAlgorithm string `json:"signature_algorithm"`

	// IsCA is true if this certificate can sign other certificates.
	IsCA bool `json:"is_ca"`
}

// Result holds TLS certificate inspection results.
type Result struct {
	// Hostname is the inspected host.
	Hostname string `json:"hostname"`

	// Port is the port number that was inspected.
	Port int `json:"port"`

	// RemoteAddr is the actual remote address that was connected to.
	RemoteAddr string `json:"remote_addr"`

	// TLSVersion is the negotiated TLS protocol version.
	TLSVersion string `json:"tls_version"`

	// CipherSuite is the negotiated TLS connection cipher suite.
	CipherSuite string `json:"cipher_suite"`

	// Chain contains the certificate chain from the endpoint.
	Chain []Certificate `json:"chain"`

	// LeafExpiresAt is when the leaf certificate expires.
	LeafExpiresAt time.Time `json:"leaf_expires_at"`

	// InspectedAt is when the inspection was performed.
	InspectedAt time.Time `json:"inspected_at"`
}

// New returns a new Inspector with default settings.
func New() *Inspector {
	return &Inspector{timeout: defaultTimeout}
}

// Inspect inspects the TLS certificate chain of the given hostname and port.
func (i *Inspector) Inspect(hostname string, port int) (Result, error) {
	var ret Result

	if port < 1 || port > maxPort {
		return ret, fmt.Errorf("invalid port: %d", port)
	}

	config := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: false,
	}

	dialer := &net.Dialer{
		Timeout: i.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(hostname, strconv.Itoa(port)), config)

	if err != nil {
		return ret, err
	}

	defer conn.Close()

	var state tls.ConnectionState
	var chain []Certificate

	if state = conn.ConnectionState(); len(state.PeerCertificates) == 0 {
		return ret, errors.New("no certificates found")
	}

	for _, cert := range state.PeerCertificates {
		certificate := Certificate{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			SerialNumber:       cert.SerialNumber.String(),
			Version:            cert.Version,
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			ExpiresIn:          time.Until(cert.NotAfter),
			PublicKeyAlgorithm: strings.ToLower(cert.PublicKeyAlgorithm.String()),
			SignatureAlgorithm: strings.ToLower(cert.SignatureAlgorithm.String()),
			IsCA:               cert.IsCA,
		}

		chain = append(chain, certificate)
	}

	ret = Result{
		Hostname:      hostname,
		Port:          port,
		RemoteAddr:    conn.RemoteAddr().String(),
		TLSVersion:    tlsVersionString(state.Version),
		CipherSuite:   tls.CipherSuiteName(state.CipherSuite),
		Chain:         chain,
		LeafExpiresAt: chain[0].NotAfter,
		InspectedAt:   time.Now().UTC(),
	}

	return ret, err
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("unknown TLS version: 0x%04x", version)
	}
}
