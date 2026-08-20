package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestPKIWorkflow(t *testing.T) {
	// 1. Generate Root CA
	rootCert, rootKey, err := GenerateRootCA("Test Root CA", "Test Org", "US", 10, "ecdsa")
	if err != nil {
		t.Fatalf("Failed to generate Root CA: %v", err)
	}
	if len(rootCert) == 0 || len(rootKey) == 0 {
		t.Fatal("Root CA cert or key is empty")
	}

	// 2. Generate Intermediate CA
	intCert, intKey, err := GenerateIntermediateCA("Test Intermediate CA", "Test Org", "US", 5, "ecdsa", rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to generate Intermediate CA: %v", err)
	}

	// 3. Sign Client Cert
	sans := []string{"example.com", "127.0.0.1"}
	clientCert, clientKey, _, _, _, err := SignCertificate("example.com", sans, 365, "ecdsa", intCert, intKey)
	if err != nil {
		t.Fatalf("Failed to sign Client Cert: %v", err)
	}
	if len(clientCert) == 0 || len(clientKey) == 0 {
		t.Fatal("Client cert or key is empty")
	}

	// 4. Verify Client Cert against Intermediate and Root
	block, _ := pem.Decode(clientCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse client cert: %v", err)
	}

	intBlock, _ := pem.Decode(intCert)
	intC, err := x509.ParseCertificate(intBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse intermediate cert: %v", err)
	}

	rootBlock, _ := pem.Decode(rootCert)
	rootC, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse root cert: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootC)

	ints := x509.NewCertPool()
	ints.AddCert(intC)

	opts := x509.VerifyOptions{
		DNSName:       "example.com",
		Roots:         roots,
		Intermediates: ints,
	}

	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	t.Log("PKI workflow successfully verified!")
}
