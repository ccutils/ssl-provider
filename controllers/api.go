package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"ssl-provider/db"
	"ssl-provider/models"
	"ssl-provider/pki"
)

// IssueRequest represents the JSON body parameters for API certificate requests
type IssueRequest struct {
	CommonName   string   `json:"common_name"`
	SANs         []string `json:"sans"`
	ValidityDays int      `json:"validity_days"`
	KeyType      string   `json:"key_type"` // rsa2048, rsa4096, ecdsa
	CSR          string   `json:"csr"`
}

// CertificateResponse represents the JSON response structure for certificate queries
type CertificateResponse struct {
	ID           uint      `json:"id"`
	CommonName   string    `json:"common_name"`
	SANs         []string  `json:"sans"`
	CertPEM      string    `json:"cert_pem"`
	KeyPEM       string    `json:"key_pem,omitempty"`
	CaPEM        string    `json:"ca_pem"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
}

// ApiListRoots returns all root certificates PEM blocks (Public Access)
func ApiListRoots(c *gin.Context) {
	var roots []models.CA
	if err := db.DB.Where("cert_type = ?", "root").Find(&roots).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch root CAs"})
		return
	}

	type RootResponse struct {
		ID         uint   `json:"id"`
		CommonName string `json:"common_name"`
		CertPEM    string `json:"cert_pem"`
	}

	resp := make([]RootResponse, len(roots))
	for i, r := range roots {
		resp[i] = RootResponse{
			ID:         r.ID,
			CommonName: r.CommonName,
			CertPEM:    r.CertPEM,
		}
	}

	c.JSON(http.StatusOK, resp)
}

// ApiIssueCertificate handles API request to sign a certificate (Authenticated)
func ApiIssueCertificate(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	var req IssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	// Validate inputs
	if req.CommonName == "" && req.CSR == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either common_name or csr must be provided"})
		return
	}

	if req.ValidityDays <= 0 {
		req.ValidityDays = 365 // Default to 1 year
	}
	if req.KeyType == "" {
		req.KeyType = "ecdsa" // Default to ECDSA P-256
	}

	// Fetch active Intermediate CA
	var activeCA models.CA
	if err := db.DB.Where("cert_type = ? AND is_active = ?", "intermediate", true).First(&activeCA).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No active Intermediate CA configured on this server"})
		return
	}

	var certPEM []byte
	var keyPEM []byte
	var serialNumber string
	var notBefore, notAfter time.Time
	var finalCommonName string
	var finalSans []string

	if req.CSR != "" {
		// Client uploaded a CSR
		var err error
		certPEM, serialNumber, notBefore, notAfter, finalCommonName, finalSans, err = pki.SignCertificateWithCSR([]byte(req.CSR), req.ValidityDays, []byte(activeCA.CertPEM), []byte(activeCA.KeyPEM))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to sign CSR: %v", err)})
			return
		}
	} else {
		// Server generates private key + signs certificate
		var err error
		finalCommonName = req.CommonName
		finalSans = req.SANs
		certPEM, keyPEM, serialNumber, notBefore, notAfter, err = pki.SignCertificate(finalCommonName, finalSans, req.ValidityDays, req.KeyType, []byte(activeCA.CertPEM), []byte(activeCA.KeyPEM))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate certificate: %v", err)})
			return
		}
	}

	cert := models.Certificate{
		UserID:       currentUser.ID,
		CaID:         activeCA.ID,
		CommonName:   finalCommonName,
		SANs:         finalSans,
		CertPEM:      string(certPEM),
		KeyPEM:       string(keyPEM),
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	if err := db.DB.Create(&cert).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store certificate in database"})
		return
	}

	c.JSON(http.StatusOK, CertificateResponse{
		ID:           cert.ID,
		CommonName:   cert.CommonName,
		SANs:         cert.SANs,
		CertPEM:      cert.CertPEM,
		KeyPEM:       cert.KeyPEM,
		CaPEM:        activeCA.CertPEM,
		SerialNumber: cert.SerialNumber,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
	})
}

// ApiDownloadCertificate downloads a certificate detail via API (Authenticated)
func ApiDownloadCertificate(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	var cert models.Certificate
	if err := db.DB.Preload("CA").First(&cert, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	// Permission enforcement
	if currentUser.Role != "admin" && cert.UserID != currentUser.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	c.JSON(http.StatusOK, CertificateResponse{
		ID:           cert.ID,
		CommonName:   cert.CommonName,
		SANs:         cert.SANs,
		CertPEM:      cert.CertPEM,
		KeyPEM:       cert.KeyPEM,
		CaPEM:        cert.CA.CertPEM,
		SerialNumber: cert.SerialNumber,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
	})
}
