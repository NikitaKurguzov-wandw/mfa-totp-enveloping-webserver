package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
	"webauth/db"
	"webauth/models"

	"github.com/golang-jwt/jwt/v5"
)

// Helper struct that will contain both json and plain text representation of the refresh token
type ExtractedTokenData struct {
	Token     models.RefreshToken
	PlainText string
}

func HashString(s string) []byte {
	h := sha256.New()

	h.Write([]byte(s))

	return h.Sum(nil)
}

// Create a pair of auth tokens and return a struct containing both. Guid - user guid. userAgent - browser user-agent value.ip - client ip
func CreateTokenPair(guid string, userAgent string, ip string) (models.ClientTokens, error) {
	accessToken, err := CreateAccessToken(guid)
	if err != nil {
		return models.ClientTokens{}, err
	}

	refreshToken, err := CreateRefreshToken(accessToken, userAgent, ip)
	if err != nil {
		return models.ClientTokens{}, err
	}

	return models.ClientTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Create new JWT token based on user guid.
//
// Created token is signed using SECRET_KEY environment value
func CreateAccessToken(guid string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": guid,
		"iss": "medods-auth",
		"aud": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	fmt.Printf("Token claims added: %+v\n", claims)
	tokenString, err := claims.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Create a new refresh token containing user identifying information
//
// This token will be paired with the provided accessToken
func CreateRefreshToken(accessToken string, userAgent string, ip string) (string, error) {
	sha := sha1.New()
	io.WriteString(sha, os.Getenv("SECRET_KEY"))
	block, err := aes.NewCipher([]byte(string(sha.Sum(nil))[0:16]))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	id, err := db.PrepareRefreshToken()
	if err != nil {
		return "", err
	}

	refreshToken := models.RefreshToken{
		AccessToken: accessToken,
		UserAgent:   userAgent,
		Ip:          ip,
		EntryId:     id,
	}

	refreshTokenString, err := json.Marshal(refreshToken)

	if err != nil {
		return "", err
	}
	err = db.SaveRefreshToken(string(HashString(string(refreshTokenString))), id)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(refreshTokenString), nil)), nil
}

// Verify validity of the access JWT token
func VerifyAccessToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func ExtractRefreshToken(token string) (ExtractedTokenData, error) {
	sha := sha1.New()
	io.WriteString(sha, os.Getenv("SECRET_KEY"))
	block, err := aes.NewCipher([]byte(string(sha.Sum(nil))[0:16]))
	if err != nil {
		return ExtractedTokenData{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ExtractedTokenData{}, err
	}

	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return ExtractedTokenData{}, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ExtractedTokenData{}, err
	}

	var refreshToken models.RefreshToken
	if err = json.Unmarshal(plain, &refreshToken); err != nil {
		return ExtractedTokenData{}, err
	}
	return ExtractedTokenData{Token: refreshToken, PlainText: string(plain)}, nil
}

// Verify validity of the refresh token. This requires having both tokens in the state that there were given to the client
//
// Refresh token will be decrypted
func VerifyRefreshToken(tokenPair models.ClientTokens) (models.RefreshToken, error) {
	refreshToken, err := ExtractRefreshToken(tokenPair.RefreshToken)
	if err != nil {
		return models.RefreshToken{}, err
	}
	isValidToken, err := db.IsRefreshTokenValid(refreshToken.Token, string(HashString(refreshToken.PlainText)))
	if err != nil {
		return models.RefreshToken{}, err
	}

	if refreshToken.Token.AccessToken != tokenPair.AccessToken || !isValidToken {
		return models.RefreshToken{}, fmt.Errorf("refresh token is paired with invalid access token")
	}
	return refreshToken.Token, nil
}
