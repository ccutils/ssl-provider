package controllers

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"ssl-provider/db"
	"ssl-provider/models"
	"ssl-provider/pki"
)

// ListCertificates renders dashboard containing certificate list
func ListCertificates(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	var certificates []models.Certificate

	if currentUser.Role == "admin" {
		// Admin sees all certificates
		db.DB.Preload("User").Preload("CA").Order("id desc").Find(&certificates)
	} else {
		// User sees only their own certificates
		db.DB.Preload("CA").Where("user_id = ?", currentUser.ID).Order("id desc").Find(&certificates)
	}

	// Fetch active Intermediate CA to know if user can generate certificates
	var activeCA models.CA
	hasActiveCA := db.DB.Where("cert_type = ? AND is_active = ?", "intermediate", true).First(&activeCA).Error == nil

	c.HTML(http.StatusOK, "user_certificates.html", gin.H{
		"user":         currentUser,
		"certificates": certificates,
		"hasActiveCA":  hasActiveCA,
		"activeTab":    "certificates",
		"error":        c.Query("error"),
		"success":      c.Query("success"),
	})
}

// IssueCertificate processes web requests to issue/sign leaf certificates
func IssueCertificate(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	cn := strings.TrimSpace(c.PostForm("common_name"))
	sansRaw := strings.TrimSpace(c.PostForm("sans"))
	daysStr := c.PostForm("validity_days")
	keyType := c.PostForm("key_type")
	csrRaw := strings.TrimSpace(c.PostForm("csr"))

	if cn == "" && csrRaw == "" {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Either Common Name or CSR is required")
		return
	}

	days, err := strconv.Atoi(daysStr)
	if err != nil || days <= 0 {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Validity days must be a positive integer")
		return
	}

	// Fetch active Intermediate CA
	var activeCA models.CA
	if err := db.DB.Where("cert_type = ? AND is_active = ?", "intermediate", true).First(&activeCA).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=No active Intermediate CA is configured. Please contact an admin.")
		return
	}

	var certPEM []byte
	var keyPEM []byte
	var serialNumber string
	var notBefore, notAfter time.Time
	var finalCommonName string
	var finalSans []string

	if csrRaw != "" {
		// Process CSR (Server does not store private key as it is client-held)
		var err error
		certPEM, serialNumber, notBefore, notAfter, finalCommonName, finalSans, err = pki.SignCertificateWithCSR([]byte(csrRaw), days, []byte(activeCA.CertPEM), []byte(activeCA.KeyPEM))
		if err != nil {
			c.Redirect(http.StatusSeeOther, fmt.Sprintf("/dashboard?error=CSR Signing failed: %v", err))
			return
		}
	} else {
		// Server-generated Private Key
		var err error
		if sansRaw != "" {
			// support both comma and line-separated SANs
			parts := strings.FieldsFunc(sansRaw, func(r rune) bool {
				return r == ',' || r == '\n' || r == '\r'
			})
			for _, p := range parts {
				trimmed := strings.TrimSpace(p)
				if trimmed != "" {
					finalSans = append(finalSans, trimmed)
				}
			}
		}
		finalCommonName = cn

		certPEM, keyPEM, serialNumber, notBefore, notAfter, err = pki.SignCertificate(finalCommonName, finalSans, days, keyType, []byte(activeCA.CertPEM), []byte(activeCA.KeyPEM))
		if err != nil {
			c.Redirect(http.StatusSeeOther, fmt.Sprintf("/dashboard?error=Certificate generation failed: %v", err))
			return
		}
	}

	cert := models.Certificate{
		UserID:       currentUser.ID,
		CaID:         activeCA.ID,
		CommonName:   finalCommonName,
		SANs:         finalSans,
		CertPEM:      string(certPEM),
		KeyPEM:       string(keyPEM), // Might be empty if CSR is used
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	if err := db.DB.Create(&cert).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Failed to save certificate record")
		return
	}

	c.Redirect(http.StatusSeeOther, "/dashboard?success=Certificate issued successfully")
}

// DownloadCertificate packages PEM contents and serves them to user
func DownloadCertificate(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid certificate ID")
		return
	}

	var cert models.Certificate
	if err := db.DB.Preload("CA").First(&cert, id).Error; err != nil {
		c.String(http.StatusNotFound, "Certificate not found")
		return
	}

	// Verify permissions
	if currentUser.Role != "admin" && cert.UserID != currentUser.ID {
		c.String(http.StatusForbidden, "Access denied")
		return
	}

	format := c.Query("format")
	baseName := strings.ReplaceAll(strings.ToLower(cert.CommonName), " ", "_")

	switch format {
	case "cert":
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.crt", baseName))
		c.Data(http.StatusOK, "application/x-x509-server-cert", []byte(cert.CertPEM))

	case "key":
		if cert.KeyPEM == "" {
			c.String(http.StatusBadRequest, "Private key is not stored on the server for CSR-based certificates")
			return
		}
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.key", baseName))
		c.Data(http.StatusOK, "application/x-pem-file", []byte(cert.KeyPEM))

	case "ca":
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=ca.crt"))
		c.Data(http.StatusOK, "application/x-x509-ca-cert", []byte(cert.CA.CertPEM))

	case "fullchain":
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s_fullchain.crt", baseName))
		c.Data(http.StatusOK, "application/x-pem-file", []byte(cert.CertPEM+"\n"+cert.CA.CertPEM))

	default: // ZIP format
		buf := new(bytes.Buffer)
		zipWriter := zip.NewWriter(buf)

		// 1. Add Certificate
		fCert, err := zipWriter.Create(baseName + ".crt")
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to build ZIP archive")
			return
		}
		fCert.Write([]byte(cert.CertPEM))

		// 2. Add Private Key (if present)
		if cert.KeyPEM != "" {
			fKey, err := zipWriter.Create(baseName + ".key")
			if err != nil {
				c.String(http.StatusInternalServerError, "Failed to build ZIP archive")
				return
			}
			fKey.Write([]byte(cert.KeyPEM))
		}

		// 3. Add Intermediate CA Cert
		fCA, err := zipWriter.Create("ca.crt")
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to build ZIP archive")
			return
		}
		fCA.Write([]byte(cert.CA.CertPEM))

		// 4. Add Nginx Full Chain Bundle Cert
		fFull, err := zipWriter.Create(baseName + "_fullchain.crt")
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to build ZIP archive")
			return
		}
		fFull.Write([]byte(cert.CertPEM + "\n" + cert.CA.CertPEM))

		zipWriter.Close()

		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s_bundle.zip", baseName))
		c.Data(http.StatusOK, "application/zip", buf.Bytes())
	}
}

// DeleteCertificate deletes a certificate record
func DeleteCertificate(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Invalid certificate ID")
		return
	}

	var cert models.Certificate
	if err := db.DB.First(&cert, id).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Certificate not found")
		return
	}

	// Verify permissions
	if currentUser.Role != "admin" && cert.UserID != currentUser.ID {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Unauthorized request")
		return
	}

	if err := db.DB.Delete(&cert).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Failed to delete certificate")
		return
	}

	c.Redirect(http.StatusSeeOther, "/dashboard?success=Certificate record deleted")
}

// ListApiKeys displays API Key generation panel
func ListApiKeys(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	var keys []models.ApiKey
	db.DB.Where("user_id = ?", currentUser.ID).Order("id desc").Find(&keys)

	session := sessions.Default(c)
	newRawKey := session.Flashes("new_api_key")
	session.Save()

	var showKey string
	if len(newRawKey) > 0 {
		showKey = newRawKey[0].(string)
	}

	c.HTML(http.StatusOK, "user_apikeys.html", gin.H{
		"user":      currentUser,
		"keys":      keys,
		"newKey":    showKey,
		"activeTab": "apikeys",
		"error":     c.Query("error"),
		"success":   c.Query("success"),
	})
}

// CreateApiKey generates a new cryptographically secure API key
func CreateApiKey(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	name := strings.TrimSpace(c.PostForm("name"))
	if name == "" {
		c.Redirect(http.StatusSeeOther, "/apikeys?error=Key description/name is required")
		return
	}

	// Generate 24 random bytes (48 character hex key)
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		c.Redirect(http.StatusSeeOther, "/apikeys?error=Key generation failed")
		return
	}

	rawKey := "sp_" + hex.EncodeToString(bytes)
	prefix := rawKey[:10] // sp_ + 7 chars

	// Hash the rawKey
	hasher := sha256.New()
	hasher.Write([]byte(rawKey))
	keyHash := hex.EncodeToString(hasher.Sum(nil))

	keyModel := models.ApiKey{
		UserID:  currentUser.ID,
		Name:    name,
		Prefix:  prefix,
		KeyHash: keyHash,
	}

	if err := db.DB.Create(&keyModel).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/apikeys?error=Failed to save API Key")
		return
	}

	// Use Flash Session to transmit raw key for single rendering
	session := sessions.Default(c)
	session.AddFlash(rawKey, "new_api_key")
	session.Save()

	c.Redirect(http.StatusSeeOther, "/apikeys?success=API Key generated successfully")
}

// DeleteApiKey revokes and deletes API Key
func DeleteApiKey(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/apikeys?error=Invalid key ID")
		return
	}

	var apiKey models.ApiKey
	if err := db.DB.First(&apiKey, id).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/apikeys?error=API Key not found")
		return
	}

	if apiKey.UserID != currentUser.ID {
		c.Redirect(http.StatusSeeOther, "/apikeys?error=Unauthorized request")
		return
	}

	if err := db.DB.Delete(&apiKey).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/apikeys?error=Failed to delete API Key")
		return
	}

	c.Redirect(http.StatusSeeOther, "/apikeys?success=API Key revoked successfully")
}
