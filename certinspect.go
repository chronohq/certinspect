// Copyright Chrono Technologies LLC
// SPDX-License-Identifier: MIT
//
// Package certinspect provides TLS certificate inspection for remote endpoints.
package certinspect

import (
	"time"
)

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
	// Domain is the inspected hostname.
	Domain string `json:"domain"`

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
