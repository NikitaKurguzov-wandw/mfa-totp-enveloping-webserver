// Package middleware provides server-side sessions and rate limiting for Gin.
package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"
	"webauth/db"
	"webauth/models"

	"github.com/gin-gonic/gin"
)

const (
	CookieName = "sid"

	// StagePending: the password was accepted but the second factor has not
	// been presented yet. Such a session can only call the MFA verify endpoint.
	StagePending = "pending"
	// StageFull: fully authenticated.
	StageFull = "full"

	ctxUserID = "userID"
)

// Sessions creates, validates and destroys cookie-backed sessions stored in the DB.
type Sessions struct {
	Secure     bool // set the Secure cookie attribute (use behind HTTPS)
	PendingTTL time.Duration
	FullTTL    time.Duration
}

var sessions *Sessions

func GetSessions() *Sessions {
	if sessions == nil {
		sessions = &Sessions{
			Secure:     false,
			PendingTTL: 5 * time.Minute,
			FullTTL:    24 * time.Hour,
		}
	}

	return sessions
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// Create stores a new session and sets its cookie on the response.
// A new random token is issued every time, which prevents session fixation.
func (s *Sessions) Create(c *gin.Context, userID string, stage string) error {
	db := db.GetDB()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	ttl := s.FullTTL
	if stage == StagePending {
		ttl = s.PendingTTL
	}
	now := time.Now().UTC()

	// Opportunistic cleanup of expired rows.
	db.Where("expires_at < ?", now).Delete(&models.Session{})

	sess := models.Session{ID: hashToken(token), UserID: userID, Stage: stage, ExpiresAt: now.Add(ttl)}
	if err := db.Create(&sess).Error; err != nil {
		return err
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(CookieName, token, int(ttl.Seconds()), "/", "", s.Secure, true)
	return nil
}

// Revoke deletes the session named by the request cookie, if any, without
// touching the response. Use it right before Create to swap sessions.
func (s *Sessions) Revoke(c *gin.Context) {
	db := db.GetDB()
	if tok, err := c.Cookie(CookieName); err == nil && tok != "" {
		db.Where("id = ?", hashToken(tok)).Delete(&models.Session{})
	}
}

// Destroy revokes the current session and clears the cookie (logout).
func (s *Sessions) Destroy(c *gin.Context) {
	s.Revoke(c)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(CookieName, "", -1, "/", "", s.Secure, true)
}

// Require returns middleware that only lets through requests whose session
// is unexpired and at exactly the given stage.
func (s *Sessions) Require(stage string) gin.HandlerFunc {
	db := db.GetDB()
	return func(c *gin.Context) {
		tok, err := c.Cookie(CookieName)
		if err != nil || tok == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var sess models.Session
		err = db.Where("id = ? AND stage = ? AND expires_at > ?", hashToken(tok), stage, time.Now().UTC()).
			First(&sess).Error
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set(ctxUserID, sess.UserID)
		c.Next()
	}
}

// UserID returns the authenticated user's ID set by Require.
func UserID(c *gin.Context) uint {
	v, _ := c.Get(ctxUserID)
	id, _ := v.(uint)
	return id
}
