package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// ParsePrivateKey parses an RSA or ECDSA private key from PEM bytes (PKCS1, PKCS8, or EC formats).
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	// Try PKCS8 format first (standard for modern keys)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS1 format (RSA)
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try EC format (ECDSA)
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("unknown or unsupported private key type")
}

// GeneratePrivateKey generates a new RSA or ECDSA key and returns it along with its PKCS8 PEM bytes.
func GeneratePrivateKey(keyType string) (crypto.PrivateKey, []byte, error) {
	var priv crypto.PrivateKey
	var err error

	switch keyType {
	case "rsa2048":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa4096":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, nil, fmt.Errorf("invalid key type: %s", keyType)
	}

	if err != nil {
		return nil, nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key to PKCS8: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	return priv, pem.EncodeToMemory(pemBlock), nil
}

// GenerateRootCA generates a self-signed Root CA certificate.
func GenerateRootCA(commonName, org, country string, validYears int, keyType string) (certPEM, keyPEM []byte, err error) {
	priv, keyBytes, err := GeneratePrivateKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(validYears, 0, 0)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	var pubKey crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(certBlock), keyBytes, nil
}

// GenerateIntermediateCA generates an Intermediate CA certificate signed by the parent Root CA.
func GenerateIntermediateCA(commonName, org, country string, validYears int, keyType string, parentCertPEM, parentKeyPEM []byte) (certPEM, keyPEM []byte, err error) {
	parentCertBlock, _ := pem.Decode(parentCertPEM)
	if parentCertBlock == nil {
		return nil, nil, errors.New("failed to decode parent certificate PEM")
	}
	parentCert, err := x509.ParseCertificate(parentCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse parent certificate: %v", err)
	}

	parentKey, err := ParsePrivateKey(parentKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse parent private key: %v", err)
	}

	priv, keyBytes, err := GeneratePrivateKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.AddDate(validYears, 0, 0)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	var pubKey crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, pubKey, parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create intermediate certificate: %v", err)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(certBlock), keyBytes, nil
}

// SignCertificate signs an end-entity (user) certificate using server-generated keys.
func SignCertificate(commonName string, sans []string, validDays int, keyType string, caCertPEM, caKeyPEM []byte) (certPEM, keyPEM []byte, serialNumberStr string, notBefore, notAfter time.Time, err error) {
	priv, keyBytes, err := GeneratePrivateKey(keyType)
	if err != nil {
		return nil, nil, "", time.Time{}, time.Time{}, err
	}

	var pubKey crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	}

	certPEM, serialNumberStr, notBefore, notAfter, err = SignCertificateWithPubKey(commonName, sans, validDays, pubKey, caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, "", time.Time{}, time.Time{}, err
	}

	return certPEM, keyBytes, serialNumberStr, notBefore, notAfter, nil
}

// SignCertificateWithCSR signs a client-provided CSR (Certificate Signing Request) using the active CA.
func SignCertificateWithCSR(csrPEM []byte, validDays int, caCertPEM, caKeyPEM []byte) (certPEM []byte, serialNumberStr string, notBefore, notAfter time.Time, commonName string, sans []string, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, "", time.Time{}, time.Time{}, "", nil, errors.New("failed to decode CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, "", nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, "", time.Time{}, time.Time{}, "", nil, fmt.Errorf("CSR signature verification failed: %v", err)
	}

	// Extract SANs
	var allSans []string
	allSans = append(allSans, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		allSans = append(allSans, ip.String())
	}

	certPEM, serialNumberStr, notBefore, notAfter, err = SignCertificateWithPubKey(csr.Subject.CommonName, allSans, validDays, csr.PublicKey, caCertPEM, caKeyPEM)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, "", nil, err
	}

	return certPEM, serialNumberStr, notBefore, notAfter, csr.Subject.CommonName, allSans, nil
}

// SignCertificateWithPubKey is a low-level helper to generate a leaf certificate signed by a CA.
func SignCertificateWithPubKey(commonName string, sans []string, validDays int, pubKey crypto.PublicKey, caCertPEM, caKeyPEM []byte) (certPEM []byte, serialNumberStr string, notBefore, notAfter time.Time, err error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return nil, "", time.Time{}, time.Time{}, errors.New("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	caKey, err := ParsePrivateKey(caKeyPEM)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("failed to generate serial number: %v", err)
	}

	notBefore = time.Now().UTC()
	notAfter = notBefore.AddDate(0, 0, validDays)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, pubKey, caKey)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("failed to generate certificate: %v", err)
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(certBlock), serialNumber.String(), notBefore, notAfter, nil
}

// CAMetadata represents parsed certificate info
type CAMetadata struct {
	SerialNumber string    `json:"serial_number"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	KeyAlgo      string    `json:"key_algo"`
}

// GetPEMCertMetadata decodes and parses certificate PEM metadata
func GetPEMCertMetadata(pemStr string) (*CAMetadata, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	keyAlgo := cert.PublicKeyAlgorithm.String()
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keyAlgo = fmt.Sprintf("RSA %d-bit", pub.Size()*8)
		}
	case x509.ECDSA:
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			keyAlgo = fmt.Sprintf("ECDSA P-%d", pub.Params().BitSize)
		}
	}

	return &CAMetadata{
		SerialNumber: cert.SerialNumber.String(),
		Issuer:       cert.Issuer.CommonName,
		Subject:      cert.Subject.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		KeyAlgo:      keyAlgo,
	}, nil
}

