package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"ssl-provider/db"
	"ssl-provider/models"
	"ssl-provider/pki"
)

// AdminDashboard renders primary admin panel
func AdminDashboard(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	var usersCount int64
	var certsCount int64
	var casCount int64

	db.DB.Model(&models.User{}).Count(&usersCount)
	db.DB.Model(&models.Certificate{}).Count(&certsCount)
	db.DB.Model(&models.CA{}).Count(&casCount)

	c.HTML(http.StatusOK, "admin_dashboard.html", gin.H{
		"user":        currentUser,
		"usersCount":  usersCount,
		"certsCount":  certsCount,
		"casCount":    casCount,
		"activeTab":   "dashboard",
	})
}

// ListUsers renders the user management screen
func ListUsers(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	var users []models.User
	db.DB.Order("id desc").Find(&users)

	c.HTML(http.StatusOK, "admin_users.html", gin.H{
		"user":      currentUser,
		"users":     users,
		"activeTab": "users",
		"error":     c.Query("error"),
		"success":   c.Query("success"),
	})
}

// CreateUser registers a new console user
func CreateUser(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")
	role := c.PostForm("role")

	if username == "" || password == "" || role == "" {
		c.Redirect(http.StatusSeeOther, "/admin/users?error=All fields are required")
		return
	}

	if role != "admin" && role != "user" {
		c.Redirect(http.StatusSeeOther, "/admin/users?error=Invalid role specification")
		return
	}

	var existing models.User
	if err := db.DB.Where("username = ?", username).First(&existing).Error; err == nil {
		c.Redirect(http.StatusSeeOther, "/admin/users?error=Username is already taken")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/users?error=Password encryption failed")
		return
	}

	user := models.User{
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
	}

	if err := db.DB.Create(&user).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/users?error=Failed to write user to database")
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin/users?success=User created successfully")
}

// DeleteUser deletes user from database
func DeleteUser(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/users?error=Invalid user ID")
		return
	}

	if uint(id) == currentUser.ID {
		c.Redirect(http.StatusSeeOther, "/admin/users?error=You cannot delete your own admin account")
		return
	}

	if err := db.DB.Delete(&models.User{}, id).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/users?error=Failed to delete user")
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin/users?success=User deleted successfully")
}

// ListCAs lists root and intermediate authorities
func ListCAs(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	var rootCAs []models.CA
	var intCAs []models.CA

	db.DB.Where("cert_type = ?", "root").Order("id desc").Find(&rootCAs)
	db.DB.Where("cert_type = ?", "intermediate").Order("id desc").Find(&intCAs)

	type CADisplay struct {
		models.CA
		SerialNumber string
		NotBefore    string
		NotAfter     string
		Issuer       string
		Subject      string
		KeyAlgo      string
	}

	displayRoots := make([]CADisplay, 0, len(rootCAs))
	for _, r := range rootCAs {
		d := CADisplay{CA: r}
		meta, err := pki.GetPEMCertMetadata(r.CertPEM)
		if err == nil {
			d.SerialNumber = meta.SerialNumber
			d.NotBefore = meta.NotBefore.Format("2006-01-02 15:04:05")
			d.NotAfter = meta.NotAfter.Format("2006-01-02 15:04:05")
			d.Issuer = meta.Issuer
			d.Subject = meta.Subject
			d.KeyAlgo = meta.KeyAlgo
		}
		displayRoots = append(displayRoots, d)
	}

	displayInts := make([]CADisplay, 0, len(intCAs))
	for _, i := range intCAs {
		d := CADisplay{CA: i}
		meta, err := pki.GetPEMCertMetadata(i.CertPEM)
		if err == nil {
			d.SerialNumber = meta.SerialNumber
			d.NotBefore = meta.NotBefore.Format("2006-01-02 15:04:05")
			d.NotAfter = meta.NotAfter.Format("2006-01-02 15:04:05")
			d.Issuer = meta.Issuer
			d.Subject = meta.Subject
			d.KeyAlgo = meta.KeyAlgo
		}
		displayInts = append(displayInts, d)
	}

	c.HTML(http.StatusOK, "admin_ca.html", gin.H{
		"user":      currentUser,
		"rootCAs":   displayRoots,
		"intCAs":    displayInts,
		"activeTab": "ca",
		"error":     c.Query("error"),
		"success":   c.Query("success"),
	})
}

// CreateRootCA generates a self-signed root authority
func CreateRootCA(c *gin.Context) {
	cn := strings.TrimSpace(c.PostForm("common_name"))
	org := strings.TrimSpace(c.PostForm("organization"))
	country := strings.TrimSpace(c.PostForm("country"))
	yearsStr := c.PostForm("validity_years")
	keyType := c.PostForm("key_type")

	if cn == "" || org == "" || country == "" || yearsStr == "" || keyType == "" {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=All parameters are required")
		return
	}

	years, err := strconv.Atoi(yearsStr)
	if err != nil || years <= 0 {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Validity period must be a positive integer")
		return
	}

	certPEM, keyPEM, err := pki.GenerateRootCA(cn, org, country, years, keyType)
	if err != nil {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/admin/ca?error=Root CA generation failed: %v", err))
		return
	}

	ca := models.CA{
		CommonName: cn,
		CertType:   "root",
		CertPEM:    string(certPEM),
		KeyPEM:     string(keyPEM),
	}

	if err := db.DB.Create(&ca).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Failed to save Root CA")
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin/ca?success=Root CA generated successfully")
}

// CreateIntermediateCA signs a secondary intermediate CA using the last created Root CA
func CreateIntermediateCA(c *gin.Context) {
	cn := strings.TrimSpace(c.PostForm("common_name"))
	org := strings.TrimSpace(c.PostForm("organization"))
	country := strings.TrimSpace(c.PostForm("country"))
	yearsStr := c.PostForm("validity_years")
	keyType := c.PostForm("key_type")

	if cn == "" || org == "" || country == "" || yearsStr == "" || keyType == "" {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=All parameters are required")
		return
	}

	years, err := strconv.Atoi(yearsStr)
	if err != nil || years <= 0 {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Validity period must be a positive integer")
		return
	}

	parentCAIDStr := c.PostForm("parent_ca_id")
	if parentCAIDStr == "" {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Parent Root CA selection is required")
		return
	}

	parentCAID, err := strconv.ParseUint(parentCAIDStr, 10, 32)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Invalid Parent Root CA ID")
		return
	}

	// Fetch specified root CA to sign this Intermediate CA
	var rootCA models.CA
	if err := db.DB.Where("id = ? AND cert_type = ?", parentCAID, "root").First(&rootCA).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Selected Parent Root CA not found.")
		return
	}

	certPEM, keyPEM, err := pki.GenerateIntermediateCA(cn, org, country, years, keyType, []byte(rootCA.CertPEM), []byte(rootCA.KeyPEM))
	if err != nil {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/admin/ca?error=Intermediate CA generation failed: %v", err))
		return
	}

	ca := models.CA{
		CommonName: cn,
		CertType:   "intermediate",
		CertPEM:    string(certPEM),
		KeyPEM:     string(keyPEM),
		IsActive:   false, // Not active by default until switched on
	}

	if err := db.DB.Create(&ca).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Failed to save Intermediate CA")
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin/ca?success=Intermediate CA generated successfully")
}

// SetActiveCA changes the currently active intermediate signing certificate
func SetActiveCA(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Invalid CA ID")
		return
	}

	var ca models.CA
	if err := db.DB.First(&ca, id).Error; err != nil || ca.CertType != "intermediate" {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Intermediate CA not found")
		return
	}

	// Begin transaction to change active CA
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		// Set all intermediate CAs to inactive
		if err := tx.Model(&models.CA{}).Where("cert_type = ?", "intermediate").Update("is_active", false).Error; err != nil {
			return err
		}
		// Set chosen CA to active
		if err := tx.Model(&ca).Update("is_active", true).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		c.Redirect(http.StatusSeeOther, "/admin/ca?error=Failed to update active CA status")
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin/ca?success=Active intermediate CA updated successfully")
}

// DownloadCACert serves raw CA PEM certificate files
func DownloadCACert(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid CA ID")
		return
	}

	var ca models.CA
	if err := db.DB.First(&ca, id).Error; err != nil {
		c.String(http.StatusNotFound, "CA not found")
		return
	}

	filename := fmt.Sprintf("%s.crt", strings.ReplaceAll(strings.ToLower(ca.CommonName), " ", "_"))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(http.StatusOK, "application/x-x509-ca-cert", []byte(ca.CertPEM))
}
