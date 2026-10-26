package handlers

import (
	"webauth/db"
	"webauth/models"

	"github.com/gin-gonic/gin"
)

// Helper function to load user data from gin context
func LoadUser(c *gin.Context) (*models.User, bool) {
	db := db.GetDB()
	userId, hasId := c.Get("userGuid")
	if !hasId {
		return nil, false
	}

	var user models.User

	if err := db.Where("guid = ?", userId).First(&user).Error; err != nil {
		return nil, false
	}

	return &user, true
}
