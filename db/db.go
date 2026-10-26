package db

import (
	"log"
	"webauth/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

func GetDB() *gorm.DB {
	if db == nil {
		var err error
		db, err = gorm.Open(sqlite.Open("stuff.db"), &gorm.Config{})
		if err != nil {
			log.Fatalf("Unable to establish connection to the db %s", err)
		}

		db.AutoMigrate(&models.User{})
		db.AutoMigrate(&models.Session{})
		db.AutoMigrate(&models.Auth{})
		db.AutoMigrate(&models.RecoveryCode{})

	}
	return db
}

func IsRefreshTokenValid(token models.RefreshToken, tokenString string) (bool, error) {
	db := GetDB()
	var auth models.Auth
	res := db.Where("id = ?", token.EntryId).First(&auth)
	if res.Error != nil {
		return false, res.Error
	}
	err := bcrypt.CompareHashAndPassword([]byte(auth.Token), []byte(tokenString))
	if err != nil {
		return false, err
	}
	return !auth.Used, nil
}

func SaveRefreshToken(token string, id int) error {
	db := GetDB()
	var auth models.Auth
	result := db.Where("id = ?", id).First(&auth)
	if result.Error != nil {
		return result.Error
	}
	encryptedToken, err := bcrypt.GenerateFromPassword([]byte(token), 14)
	if err != nil {
		return err
	}
	auth.Token = string(encryptedToken)
	log.Printf("trying to insert %s", auth.Token)
	db.Save(&auth)
	return nil
}

// Create new entry in the token table for the future refresh token
func PrepareRefreshToken() (int, error) {
	db := GetDB()
	auth := models.Auth{
		Used: false,
	}
	result := db.Create(&auth)
	if result.Error != nil {
		return 0, result.Error
	}
	return auth.Id, nil
}

// Mark token with a given id as used, preventing it being reused in the future
func InvalidateToken(id int) error {
	db := GetDB()
	var auth models.Auth
	result := db.Where("id = ?", id).First(&auth)
	if result.Error != nil {
		return result.Error
	}
	auth.Used = true
	db.Save(&auth)
	return nil
}
