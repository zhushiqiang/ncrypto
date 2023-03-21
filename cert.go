package ncrypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	kCertificatePrefix = "-----BEGIN CERTIFICATE-----"
	kCertificateSuffix = "-----END CERTIFICATE-----"
)

var (
	ErrFailedToLoadCertificate = errors.New("failed to load certificate")
)

func FormatCertificate(raw string) []byte {
	return formatKey(raw, kCertificatePrefix, kCertificateSuffix, 76)
}

func ParseCertificate(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, ErrFailedToLoadCertificate
	}
	csr, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}
