package models

import (
	"fmt"
	"time"
)

type ClientTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshToken struct {
	AccessToken string `json:"access_token"`
	UserAgent   string `json:"user_agent"`
	Ip          string `json:"ip"`
	EntryId     int    `json:"entry_id"`
}

type User struct {
	Guid     string `gorm:"primaryKey"`
	Password string
	Email    string

	TOTPEnabled    bool
	TOTPKeyID      string
	TOTPWrappedDEK []byte
	TOTPCiphertext []byte
	TOTPLastStep   int64
}

func (u *User) TOTPAAD() []byte {
	return fmt.Appendf(nil, "user:%s:totp", u.Guid)
}

type RecoveryCode struct {
	Guid     string `gorm:"primaryKey"`
	UserGuid string `gorm:"index;not null"`
	CodeHash []byte `gorm:"uniqueIndex;not null"`
	UsedAt   *time.Time
}

// Session is a server-side session. ID is the hex SHA-256 of the random
// cookie token, so a database leak does not yield usable session cookies.
type Session struct {
	ID        string `gorm:"primaryKey"`
	UserID    string
	Stage     string    `gorm:"not null"` // "pending" (password ok, MFA outstanding) or "full"
	ExpiresAt time.Time `gorm:"index;not null"`
	CreatedAt time.Time
}

type Auth struct {
	Id    int `gorm:"primaryKey"`
	Token string
	Used  bool
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type CodeConfirmRequest struct {
	Code string `json:"code" binding:"required"`
}

type MfaLoginRequest struct {
	Code     string `json:"code"`
	Recovery string `json:"recovery"`
}

type RefreshRequestBody struct {
	RefreshToken string `json:"refresh_token" `
}
