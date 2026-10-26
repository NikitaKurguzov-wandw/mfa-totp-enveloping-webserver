package handlers

import (
	"log"
	"net/http"
	"webauth/db"
	"webauth/models"
	"webauth/token"

	"github.com/gin-gonic/gin"
)

// Middleware that will stop user from accessing routes without authentication
func AuthMiddleware(c *gin.Context) {
	accessTokenString, err := c.Cookie("access")
	if err != nil {
		log.Printf("Token verification failed: %v\\n", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	accessToken, err := token.VerifyAccessToken(accessTokenString)
	if err != nil {
		log.Printf("Token verification failed: %v\\n", err)
		ClearAccessTokens(c)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	userId, err := accessToken.Claims.GetSubject()
	if err != nil {
		log.Printf("Token verification failed: %v\\n", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		ClearAccessTokens(c)
		return
	}
	c.Set("userGuid", userId)
	c.Next()
}

// / Check if user has passed the email verification
func MultifactorAuthMiddleware(c *gin.Context) {
	db := db.GetDB()

	var loginRequest models.LoginRequest

	if err := c.BindJSON(&loginRequest); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
	}

	var user models.User
	result := db.Where("email = ?", loginRequest.Email).First(&user)
	if result.Error != nil {
		c.AbortWithError(http.StatusInternalServerError, result.Error)
	}

	c.Next()
}
