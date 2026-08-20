package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"ssl-provider/config"
	"ssl-provider/controllers"
	"ssl-provider/db"
	"ssl-provider/middleware"
)

//go:embed templates
var templatesFS embed.FS

func main() {
	// 1. Load configurations
	config.LoadConfig()

	// 2. Connect to database and run migrations
	db.InitDB()

	// 3. Initialize Gin Router
	router := gin.Default()

	// Configure template parser using go:embed filesystem
	tmpl := template.New("").Funcs(template.FuncMap{
		"now": func() time.Time { return time.Now() },
	})
	tmpl = template.Must(tmpl.ParseFS(templatesFS, "templates/*.html", "templates/layouts/*.html"))
	router.SetHTMLTemplate(tmpl)

	// Configure Cookie-based session storage
	store := cookie.NewStore([]byte(config.AppConfig.SessionSecret))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		Secure:   false,     // Must be false to allow session cookie transmission over HTTP
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Prevents redirection-based cookie drop
	})
	router.Use(sessions.Sessions("ssl_provider_session", store))

	// 4. Routes Setup
	// Root Redirect
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusSeeOther, "/dashboard")
	})

	// Public Web routes
	router.GET("/login", controllers.ShowLogin)
	router.POST("/login", controllers.Login)
	router.GET("/logout", controllers.Logout)

	// Authenticated Console routes
	authGroup := router.Group("/")
	authGroup.Use(middleware.WebSessionAuth())
	{
		authGroup.GET("/dashboard", controllers.ListCertificates)
		authGroup.POST("/user/change-password", controllers.ChangePassword)

		// Certificates management
		authGroup.POST("/certificates/issue", controllers.IssueCertificate)
		authGroup.GET("/certificates/download/:id", controllers.DownloadCertificate)
		authGroup.POST("/certificates/delete/:id", controllers.DeleteCertificate)

		// API Keys management
		authGroup.GET("/apikeys", controllers.ListApiKeys)
		authGroup.POST("/apikeys/create", controllers.CreateApiKey)
		authGroup.POST("/apikeys/delete/:id", controllers.DeleteApiKey)
	}

	// Admin-only Console routes
	adminGroup := router.Group("/admin")
	adminGroup.Use(middleware.WebSessionAuth(), middleware.AdminOnly())
	{
		adminGroup.GET("/", func(c *gin.Context) {
			c.Redirect(http.StatusSeeOther, "/admin/ca")
		})

		// User accounts management
		adminGroup.GET("/users", controllers.ListUsers)
		adminGroup.POST("/users/create", controllers.CreateUser)
		adminGroup.POST("/users/delete/:id", controllers.DeleteUser)

		// CA management
		adminGroup.GET("/ca", controllers.ListCAs)
		adminGroup.POST("/ca/root/generate", controllers.CreateRootCA)
		adminGroup.POST("/ca/intermediate/generate", controllers.CreateIntermediateCA)
		adminGroup.POST("/ca/activate/:id", controllers.SetActiveCA)
		adminGroup.GET("/ca/download/:id", controllers.DownloadCACert)
	}

	// Public API Endpoints
	apiPublic := router.Group("/api/v1")
	{
		apiPublic.GET("/ca/roots", controllers.ApiListRoots)
	}

	// Authenticated API Endpoints
	apiPrivate := router.Group("/api/v1")
	apiPrivate.Use(middleware.APIKeyAuth())
	{
		apiPrivate.POST("/certificates", controllers.ApiIssueCertificate)
		apiPrivate.GET("/certificates/:id/download", controllers.ApiDownloadCertificate)
	}

	// 5. Start Server
	log.Printf("Starting SSL Provider server on port %s...", config.AppConfig.Port)
	if err := router.Run(":" + config.AppConfig.Port); err != nil {
		log.Fatalf("Failed to run HTTP server: %v", err)
	}
}
