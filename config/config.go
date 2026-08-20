package config

import (
	"os"
)

type Config struct {
	DBType        string // sqlite, mysql, postgres
	DBDSN         string
	Port          string
	SessionSecret string
}

var AppConfig Config

func LoadConfig() {
	AppConfig = Config{
		DBType:        getEnv("DB_TYPE", "sqlite"),
		DBDSN:         getEnv("DB_DSN", "ssl_provider.db"),
		Port:          getEnv("PORT", "8080"),
		SessionSecret: getEnv("SESSION_SECRET", "super-secret-session-key-12345"),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
