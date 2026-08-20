package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// StringArray is a custom type to handle database JSON arrays or strings
type StringArray []string

func (a StringArray) Value() (driver.Value, error) {
	return json.Marshal(a)
}

func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("unsupported type for StringArray scan: %T", value)
	}

	return json.Unmarshal(bytes, &a)
}

// User model represents web console users
type User struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Username     string     `gorm:"uniqueIndex;size:100;not null" json:"username"`
	PasswordHash string     `gorm:"not null" json:"-"`
	Role         string     `gorm:"size:20;not null;default:'user'" json:"role"` // "admin" or "user"
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Certificates []Certificate `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	ApiKeys      []ApiKey      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// ApiKey model for authenticating CLI or third-party client API requests
type ApiKey struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"not null" json:"user_id"`
	User      User      `gorm:"foreignKey:UserID" json:"-"`
	Name      string    `gorm:"size:100;not null" json:"name"`
	KeyHash   string    `gorm:"uniqueIndex;not null" json:"-"`
	Prefix    string    `gorm:"size:10;not null" json:"prefix"` // e.g. "sp_a1b2c3"
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CA model represents Certificate Authority certs (both Root and Intermediate CAs)
type CA struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	CommonName string    `gorm:"size:255;not null" json:"common_name"`
	CertType   string    `gorm:"size:50;not null" json:"cert_type"` // "root" or "intermediate"
	CertPEM    string    `gorm:"type:text;not null" json:"cert_pem"`
	KeyPEM     string    `gorm:"type:text;not null" json:"-"` // Private Key PEM
	IsActive   bool      `gorm:"default:false" json:"is_active"` // Currently active CA for signing
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Certificate model represents end-entity user-issued certificates
type Certificate struct {
	ID           uint        `gorm:"primaryKey" json:"id"`
	UserID       uint        `gorm:"not null" json:"user_id"`
	User         User        `gorm:"foreignKey:UserID" json:"-"`
	CaID         uint        `gorm:"not null" json:"ca_id"`
	CA           CA          `gorm:"foreignKey:CaID" json:"-"`
	CommonName   string      `gorm:"size:255;not null" json:"common_name"`
	SANs         StringArray `gorm:"type:text" json:"sans"` // Store list of SANs as JSON array
	CertPEM      string      `gorm:"type:text;not null" json:"cert_pem"`
	KeyPEM       string      `gorm:"type:text" json:"key_pem,omitempty"` // Server-generated key (empty if signed from custom CSR)
	SerialNumber string      `gorm:"size:128;not null" json:"serial_number"`
	NotBefore    time.Time   `json:"not_before"`
	NotAfter     time.Time   `json:"not_after"`
	CreatedAt    time.Time   `json:"created_at"`
}
