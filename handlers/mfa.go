package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"webauth/db"
	"webauth/envelope"
	"webauth/models"
	"webauth/totp"

	"github.com/beevik/guid"
	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
	"gorm.io/gorm"
)

func GetIssuer() string {
	return "goblinarethebest.com"
}

const recoveryCodeCount = 10

func EnableMfa(c *gin.Context) {
	db := db.GetDB()
	user, ok := LoadUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	// Re-enrolling while TOTP is on would let a hijacked session swap the
	// authenticator. Make the user disable it first (which needs a valid code).
	if user.TOTPEnabled {
		c.AbortWithError(http.StatusConflict, fmt.Errorf("totp already enabled; disable it first"))
		return
	}

	secret, err := totp.NewTOTPSecret()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	defer envelope.Wipe(secret)

	env, err := envelope.GetKeyring().Encrypt(secret, user.TOTPAAD())
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	err = db.Model(&models.User{}).Where("guid = ?", user.Guid).Updates(map[string]any{
		"totp_key_id":      env.KeyId,
		"totp_wrapped_dek": env.WrappedDEK,
		"totp_ciphertext":  env.Ciphertext,
		"totp_enabled":     false,
		"totp_last_step":   0,
	}).Error
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"qr_url": "mfa/enroll/qr"})

}

// openSecret decrypts the user's stored TOTP secret. The caller should wipe it.
func OpenSecret(u *models.User) ([]byte, error) {
	return envelope.GetKeyring().Decrypt(&envelope.Envelope{
		KeyId:      u.TOTPKeyID,
		WrappedDEK: u.TOTPWrappedDEK,
		Ciphertext: u.TOTPCiphertext,
	}, u.TOTPAAD())
}

// checkTOTP decrypts the stored secret, verifies the code and enforces replay
// protection. The conditional UPDATE is atomic: of two concurrent requests
// presenting the same code only one can advance totp_last_step.
func CheckTOTP(u *models.User, code string) bool {
	secret, err := OpenSecret(u)
	if err != nil {
		return false
	}
	defer envelope.Wipe(secret)

	step, ok := totp.VerifyTOTP(secret, code, time.Now().UTC(), 2)
	if !ok {
		return false
	}
	res := db.GetDB().Model(&models.User{}).
		Where("guid = ? AND totp_last_step < ?", u.Guid, step).
		Update("totp_last_step", step)
	return res.Error == nil && res.RowsAffected == 1
}

func cleanCode(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), " ", "")
}

// useRecoveryCode marks a matching unused code as used. The single conditional
// UPDATE makes consumption atomic, so a code can never be spent twice.
func UseRecoveryCode(userID string, code string) bool {
	res := db.GetDB().Model(&models.RecoveryCode{}).
		Where("user_guid = ? AND code_hash = ? AND used_at IS NULL", userID, hashRecovery(code)).
		Update("used_at", time.Now().UTC())
	return res.Error == nil && res.RowsAffected == 1
}

func VerifyLogin(c *gin.Context) {
	var req models.MfaLoginRequest

	if err := c.BindJSON(&req); err != nil {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Missing MFA credentials"))
		return
	}
	user, hasUser := LoadUser(c)
	if !hasUser {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User must be logged in with access cookies present"})
		return
	}

	good := false
	if user.TOTPEnabled {
		switch {
		case cleanCode(req.Code) != "":
			good = CheckTOTP(user, cleanCode(req.Code))
		case strings.TrimSpace(req.Recovery) != "":
			good = UseRecoveryCode(user.Guid, req.Recovery)
		}
	}

	if !good {
		c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid code"))
		return
	}

	GetSessions().Revoke(c)
	if err := GetSessions().Create(c, user.Guid, StageFull); err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to create session"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func MfaQr(c *gin.Context) {
	keyring := envelope.GetKeyring()

	user, hasUser := LoadUser(c)
	if !hasUser {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if user.TOTPEnabled {
		c.String(http.StatusConflict, "TOTP is already enabled")
		return
	}

	if len(user.TOTPCiphertext) == 0 {
		c.String(http.StatusNotFound, "No enrollment pending")
		return
	}

	secret, err := keyring.Decrypt(&envelope.Envelope{
		KeyId:      user.TOTPKeyID,
		WrappedDEK: user.TOTPWrappedDEK,
		Ciphertext: user.TOTPCiphertext,
	}, user.TOTPAAD())
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	uri := totp.ProvisioningURI(GetIssuer(), user.Email, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, "image/png", png)
}

func hashRecovery(code string) []byte {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(norm))
	return sum[:]
}

func issueRecoveryCodes(tx *gorm.DB, userID string) ([]string, error) {
	// Regenerating invalidates the previous set.
	if err := tx.Where("user_guid = ?", userID).Delete(&models.RecoveryCode{}).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		raw := make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return nil, err
		}
		s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)[:12]
		display := s[:4] + "-" + s[4:8] + "-" + s[8:]
		id := guid.NewString()
		if err := tx.Create(&models.RecoveryCode{Guid: id, UserGuid: userID, CodeHash: hashRecovery(display)}).Error; err != nil {
			return nil, err
		}
		out = append(out, display)
	}
	return out, nil
}

func ConfirmCode(c *gin.Context) {
	db := db.GetDB()
	user, hasUser := LoadUser(c)
	if !hasUser {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	var req models.CodeConfirmRequest

	if err := c.BindJSON(&req); err != nil {
		c.String(http.StatusBadRequest, "Missing code data")
		return
	}

	if user.TOTPEnabled {
		c.String(http.StatusConflict, "TOTP already enabled")
		return
	}
	if len(user.TOTPCiphertext) == 0 {
		c.String(http.StatusNotFound, "No enrollment pending")
		return
	}

	var recoveryCodes []string

	err := db.Transaction(func(trans *gorm.DB) error {
		if err := trans.Model(&user).Update("totp_enabled", true).Error; err != nil {
			return err
		}
		var err error
		recoveryCodes, err = issueRecoveryCodes(trans, user.Guid)
		return err
	})

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	// TODO: Add recovery code generation
	c.JSON(http.StatusOK, gin.H{"recovery_codes": recoveryCodes})
}
