package db

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"ssl-provider/config"
	"ssl-provider/models"
)

var DB *gorm.DB

func InitDB() {
	var err error
	dbType := config.AppConfig.DBType
	dsn := config.AppConfig.DBDSN

	log.Printf("Connecting to database: type=%s, dsn=%s", dbType, dsn)

	switch dbType {
	case "mysql":
		DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	case "postgres":
		DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	case "sqlite":
		DB, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	default:
		log.Fatalf("Unsupported database type: %s", dbType)
	}

	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connection established. Running auto-migrations...")

	// Perform migrations
	err = DB.AutoMigrate(
		&models.User{},
		&models.ApiKey{},
		&models.CA{},
		&models.Certificate{},
	)
	if err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}

	log.Println("Migrations completed. Seeding default data...")
	seedDefaultData()
}

func seedDefaultData() {
	var count int64
	DB.Model(&models.User{}).Count(&count)
	if count == 0 {
		log.Println("No users found. Seeding default admin user (admin / admin123)...")
		hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Failed to hash default password: %v", err)
		}

		admin := models.User{
			Username:     "admin",
			PasswordHash: string(hash),
			Role:         "admin",
		}
		if err := DB.Create(&admin).Error; err != nil {
			log.Fatalf("Failed to seed default admin user: %v", err)
		}
		fmt.Println("==================================================")
		fmt.Println("Created default admin user: admin / admin123")
		fmt.Println("==================================================")
	}
}
