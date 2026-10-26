package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/url"
	"time"
)

const (
	Period = 30
	Digits = 6
)

func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, 20) // 160 bits, per RFC 4226 recommendation
	_, err := io.ReadFull(rand.Reader, s)
	return s, err
}

// Helper function to make it cleaner
func Base32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

func ProvisioningURI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", Base32(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s:%s?%s",
		url.PathEscape(issuer), url.PathEscape(account), q.Encode())
}

// RFC 4226 HOTP
func HOTP(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f // dynamic truncation
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, code%uint32(math.Pow10(Digits)))
}

// VerifyTOTP checks the current step +/- window to tolerate clock drift.
// It returns the matched step so the caller can reject replays.
func VerifyTOTP(secret []byte, code string, now time.Time, window int) (int64, bool) {
	step := now.Unix() / Period
	matched := int64(-1)
	for i := -window; i <= window; i++ {
		cand := HOTP(secret, uint64(step+int64(i)))
		// Constant-time compare; don't break early so timing doesn't leak which offset matched.
		if subtle.ConstantTimeCompare([]byte(cand), []byte(code)) == 1 {
			matched = step + int64(i)
		}
	}
	return matched, matched >= 0
}
