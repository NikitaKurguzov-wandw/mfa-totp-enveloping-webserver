package handlers

import (
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"webauth/db"
	"webauth/models"
	"webauth/token"

	"github.com/beevik/guid"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordLen = 8
	maxPasswordLen = 72 // bcrypt only uses the first 72 bytes
)

func RegisterUser(c *gin.Context) {

	db := db.GetDB()
	var userData models.LoginRequest

	if err := c.BindJSON(&userData); err != nil {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Missing credentials"))
	}
	email := strings.ToLower(strings.TrimSpace(userData.Email))
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email || len(email) > 254 {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("invalid email address"))
		return
	}
	if len(userData.Password) < minPasswordLen || len(userData.Password) > maxPasswordLen {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("password must be 8 to 72 bytes long"))
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("internal error"))
		return
	}

	userGuid := guid.NewString()

	var count int64
	db.Model(&models.User{}).Where("email = ?", email).Count(&count)
	if count > 0 {
		c.AbortWithError(http.StatusConflict, fmt.Errorf("Email already in use"))
		return
	}

	if err := db.Create(&models.User{Guid: userGuid, Email: email, Password: string(hash)}).Error; err != nil {
		c.AbortWithError(http.StatusConflict, err)
	}

	c.JSON(http.StatusOK, gin.H{"guid": userGuid})
}

func UserInfo(c *gin.Context) {
	user, has := LoadUser(c)
	if !has {
		c.Status(http.StatusUnauthorized)

		return
	}

	c.JSON(http.StatusOK, user)
}

func VerifyEmail(ctx *gin.Context) {

}

func LoginUser(ctx *gin.Context) {
	var loginRequest models.LoginRequest
	if err := ctx.BindJSON(&loginRequest); err != nil {
		ctx.String(http.StatusBadRequest, "Missing login credentials")
		return
	}
	db := db.GetDB()
	log.Printf("User: %s", loginRequest.Email)
	var user models.User
	userResult := db.Where("email = ?", loginRequest.Email).First(&user)
	if userResult.Error != nil {
		ctx.String(http.StatusNotFound, "No user with given guid found")
		return
	}
	if user.Email != loginRequest.Email || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password)) != nil {
		ctx.String(http.StatusBadRequest, "Invalid credentials")
		return
	}

	stage := StageFull

	if user.TOTPEnabled {
		stage = StagePending
	}
	GetSessions().Revoke(ctx) // drop any session the client already had
	if err := GetSessions().Create(ctx, user.Guid, stage); err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	tokens, err := token.CreateTokenPair(user.Guid, ctx.Request.UserAgent(), ctx.ClientIP())
	if err != nil {
		ctx.String(http.StatusInternalServerError, fmt.Sprintf("Failed failed to create token %v", err))
	}
	//ctx.SetCookie("access", tokens.AccessToken, 3600, "/", "localhost", false, true)
	//ctx.SetCookie("refresh", tokens.RefreshToken, 36000, "/", "localhost", false, true)

	ctx.SetCookieData(&http.Cookie{
		Name:     "access",
		Value:    tokens.AccessToken,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(time.Hour),
		MaxAge:   86400,
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	})
	ctx.SetCookieData(&http.Cookie{
		Name:     "refresh",
		Value:    tokens.RefreshToken,
		Path:     "/",
		Domain:   "localhost",
		Expires:  time.Now().Add(24 * time.Hour),
		MaxAge:   86400,
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	})

	// this is just a placeholder for testing purposes
	ctx.JSON(http.StatusOK, gin.H{"tokens": tokens, "mfa_required": user.TOTPEnabled})
}

func LogoutUser(ctx *gin.Context) {
	ClearAccessTokens(ctx)
	ctx.Status(http.StatusOK)
}

func Refresh(ctx *gin.Context) {
	accessTokenString, err := ctx.Cookie("access")
	if err != nil {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	var refreshRequest models.RefreshRequestBody
	if err := ctx.BindJSON(&refreshRequest); err != nil {
		ctx.String(http.StatusBadRequest, "Missing refresh token")
		return
	}

	userId, hasId := ctx.Get("userGuid")
	if !hasId {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	refreshToken, err := token.VerifyRefreshToken(models.ClientTokens{AccessToken: accessTokenString, RefreshToken: refreshRequest.RefreshToken})
	if err != nil {
		ctx.String(http.StatusUnauthorized, "Invalid token pair")
		return
	}
	if refreshToken.UserAgent != ctx.Request.UserAgent() {
		ctx.Redirect(http.StatusSeeOther, "/logout")
		return
	}
	db.InvalidateToken(refreshToken.EntryId)
	if userIdStr, ok := userId.(string); ok {
		tokens, err := token.CreateTokenPair(userIdStr, ctx.Request.UserAgent(), ctx.ClientIP())
		if err != nil {
			ctx.String(http.StatusInternalServerError, fmt.Sprintf("Failed to create token %v", err))
			return
		}
		//
		ctx.SetCookieData(&http.Cookie{
			Name:     "access",
			Value:    tokens.AccessToken,
			Path:     "/",
			Domain:   "localhost",
			Expires:  time.Now().Add(time.Hour),
			MaxAge:   86400,
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteDefaultMode,
		})
		ctx.SetCookieData(&http.Cookie{
			Name:     "refresh",
			Value:    tokens.RefreshToken,
			Path:     "/",
			Domain:   "localhost",
			Expires:  time.Now().Add(24 * time.Hour),
			MaxAge:   86400,
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteDefaultMode,
		})
		//ctx.SetCookie("access", tokens.AccessToken, 3600, "/", "localhost", false, true)
		//ctx.SetCookie("refresh", tokens.RefreshToken, 3600*24, "/", "localhost", false, true)
		ctx.JSON(http.StatusOK, tokens)
	} else {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}

}

func ClearAccessTokens(ctx *gin.Context) error {
	ctx.Set("guid", nil)
	ctx.SetCookie("access", "", -1, "/", "localhost", false, true)
	refresh, err := ctx.Cookie("refresh")

	if err != nil {
		// if we don't have refresh then just remove the access and move on

		return err
	}

	// since we have refresh token we have to invalidate it in db, to prevent it from being reused
	token, err := token.ExtractRefreshToken(refresh)
	if err != nil {
		// if we don't have refresh then just remove the access and move on

		return err
	}
	// this way you can't reuse the refresh token
	db.InvalidateToken(token.Token.EntryId)
	return nil
}

func VerifyUser(ctx *gin.Context) {

}

func SecretPage(ctx *gin.Context) {
	ctx.String(http.StatusOK, "if you see this you logged in")
}
