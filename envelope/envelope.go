package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"webauth/models"

	"gorm.io/gorm"
)

const KeySize = 32

type Keyring struct {
	CurrentId string
	Keys      map[string][]byte
}

type Envelope struct {
	KeyId      string
	WrappedDEK []byte // nonce || AES-GCM(KEK, DEK)
	Ciphertext []byte // nonce || AES-GCM(DEK, plaintext)
}

func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Global var but that's common for go when done with a singleton like pattern
var keyring *Keyring

func NewKeyring(CurrentId string, keys map[string][]byte) *Keyring {

	return &Keyring{
		CurrentId: CurrentId,
		Keys:      keys,
	}
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != KeySize {
				return nil, fmt.Errorf("key must decode to %d bytes, got %d", KeySize, len(b))
			}
			return b, nil
		}
	}
	return nil, errors.New("key is not valid base64")
}

func GetKeyring() *Keyring {
	if keyring == nil {
		keys := map[string][]byte{}
		for _, kv := range os.Environ() {
			name, val, ok := strings.Cut(kv, "=")
			if !ok || !strings.HasPrefix(name, "KEK_") {
				continue
			}
			id := strings.ToLower(strings.TrimPrefix(name, "KEK_"))
			key, err := decodeKey(val)
			if err != nil {
				log.Fatalf("%s: %e", name, err)
			}
			keys[id] = key
		}
		// load this from .env later
		keyring = &Keyring{CurrentId: strings.ToLower(os.Getenv("ACTIVE_KEK_ID")), Keys: keys}
	}
	return keyring
}

func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(key, data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}

// aad binds the ciphertext to its row (e.g. "user:42:totp"), so an attacker
// with DB write access can't swap one user's encrypted secret into another's.
func (k *Keyring) Encrypt(plaintext, aad []byte) (*Envelope, error) {
	kek := k.Keys[k.CurrentId]

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	ct, err := gcmSeal(dek, plaintext, aad)
	if err != nil {
		return nil, err
	}
	wrapped, err := gcmSeal(kek, dek, []byte(k.CurrentId))
	if err != nil {
		return nil, err
	}
	return &Envelope{KeyId: k.CurrentId, WrappedDEK: wrapped, Ciphertext: ct}, nil
}

func (k *Keyring) Decrypt(e *Envelope, aad []byte) ([]byte, error) {
	kek, ok := k.Keys[e.KeyId]
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", e.KeyId)
	}
	dek, err := gcmOpen(kek, e.WrappedDEK, []byte(e.KeyId))
	if err != nil {
		return nil, err
	}
	return gcmOpen(dek, e.Ciphertext, aad)
}

// Rewrap re-encrypts only the small wrapped DEK under the current KEK. The
// (potentially large) ciphertext is untouched, which is what makes KEK
// rotation cheap. e.WrappedDEK and e.KeyId are updated in place.
func (k *Keyring) Rewrap(e *Envelope) error {
	oldKEK, ok := k.Keys[e.KeyId]
	if !ok {
		return fmt.Errorf("unknown key id %q", e.KeyId)
	}
	dek, err := gcmOpen(oldKEK, e.WrappedDEK, []byte(e.KeyId))
	if err != nil {
		return err
	}
	defer Wipe(dek)
	wrapped, err := gcmSeal(k.Keys[k.CurrentId], dek, []byte(k.CurrentId))
	if err != nil {
		return err
	}
	e.WrappedDEK, e.KeyId = wrapped, k.CurrentId
	return nil
}

// RotateKeys rewraps the DEK of every user whose TOTP envelope is wrapped by a
// KEK other than kr.CurrentId. Only the small wrapped DEK is rewritten; the
// encrypted TOTP secret itself is untouched. It returns how many rows changed.
//
// Each update is conditional on the row still holding the exact wrapped DEK
// that was read, so a concurrent re-enrolment is never overwritten with stale
// data (that row is simply skipped and picked up on the next run).
func RotateKeys(db *gorm.DB, kr *Keyring) (int, error) {
	rotated := 0
	var users []models.User

	// NOTE: use db (not the tx passed to the callback) for updates, because the
	// callback's tx still carries the SELECT's conditions and destination.
	res := db.Where("totp_key_id <> '' AND totp_key_id <> ?", kr.CurrentId).
		FindInBatches(&users, 100, func(_ *gorm.DB, _ int) error {
			for i := range users {
				u := &users[i]
				oldKeyID, oldWrapped := u.TOTPKeyID, u.TOTPWrappedDEK

				env := &Envelope{KeyId: oldKeyID, WrappedDEK: append([]byte(nil), oldWrapped...)}
				if err := kr.Rewrap(env); err != nil {
					return fmt.Errorf("user %d: %w", u.Guid, err)
				}
				upd := db.Model(&models.User{}).
					Where("guid = ? AND totp_key_id = ? AND totp_wrapped_dek = ?", u.Guid, oldKeyID, oldWrapped).
					Updates(map[string]any{
						"totp_key_id":      env.KeyId,
						"totp_wrapped_dek": env.WrappedDEK,
					})
				if upd.Error != nil {
					return upd.Error
				}
				rotated += int(upd.RowsAffected)
			}
			return nil
		})
	return rotated, res.Error
}
