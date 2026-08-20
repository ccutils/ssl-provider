package controllers

import (
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"ssl-provider/db"
	"ssl-provider/models"
)

// ShowLogin renders login screen
func ShowLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

// Login handles credentials submission
func Login(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")
	session := sessions.Default(c)

	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{"error": "Username and password are required"})
		return
	}

	var user models.User
	if err := db.DB.Where("username = ?", username).First(&user).Error; err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Invalid username or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Invalid username or password"})
		return
	}

	// Save session
	session.Set("user_id", user.ID)
	session.Save()

	// Redirect back or to dashboard
	redirectTo := "/dashboard"
	if savedRedirect := session.Get("redirect_to"); savedRedirect != nil {
		redirectTo = savedRedirect.(string)
		session.Delete("redirect_to")
		session.Save()
	}

	c.Redirect(http.StatusSeeOther, redirectTo)
}

// Logout terminates user session
func Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusSeeOther, "/login")
}

// ChangePassword allows the user to update their own password
func ChangePassword(c *gin.Context) {
	val, _ := c.Get("user")
	currentUser := val.(*models.User)

	oldPassword := c.PostForm("old_password")
	newPassword := c.PostForm("new_password")

	if oldPassword == "" || newPassword == "" {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=All password fields are required")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentUser.PasswordHash), []byte(oldPassword)); err != nil {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Incorrect old password")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Failed to process password")
		return
	}

	currentUser.PasswordHash = string(newHash)
	if err := db.DB.Save(currentUser).Error; err != nil {
		c.Redirect(http.StatusSeeOther, "/dashboard?error=Failed to update password")
		return
	}

	c.Redirect(http.StatusSeeOther, "/dashboard?success=Password updated successfully")
}
