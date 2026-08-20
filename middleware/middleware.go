package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"ssl-provider/db"
	"ssl-provider/models"
)

// WebSessionAuth ensures the user is logged in via Web UI session
func WebSessionAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("user_id")
		if userID == nil {
			// Save current path to redirect back after login
			session.Set("redirect_to", c.Request.URL.Path)
			session.Save()
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		var user models.User
		if err := db.DB.First(&user, userID).Error; err != nil {
			session.Clear()
			session.Save()
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		c.Set("user", &user)
		c.Next()
	}
}

// AdminOnly restricts access to administrators only
func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get("user")
		if !exists {
			c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Unauthorized", "message": "You must be logged in."})
			c.Abort()
			return
		}

		user := val.(*models.User)
		if user.Role != "admin" {
			c.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Forbidden", "message": "Only administrators can access this page."})
			c.Abort()
			return
		}

		c.Next()
	}
}

// APIKeyAuth validates API keys sent via X-API-Key header
func APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKeyRaw := c.GetHeader("X-API-Key")
		if apiKeyRaw == "" {
			// Also check Query parameter for download compatibility
			apiKeyRaw = c.Query("api_key")
		}

		apiKeyRaw = strings.TrimSpace(apiKeyRaw)
		if apiKeyRaw == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API Key is required via X-API-Key header or api_key query parameter"})
			c.Abort()
			return
		}

		// Hash the incoming raw key to match against database
		hasher := sha256.New()
		hasher.Write([]byte(apiKeyRaw))
		hashedKey := hex.EncodeToString(hasher.Sum(nil))

		var apiKey models.ApiKey
		if err := db.DB.Preload("User").Where("key_hash = ?", hashedKey).First(&apiKey).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API Key"})
			c.Abort()
			return
		}

		c.Set("user", &apiKey.User)
		c.Next()
	}
}
