package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"webauth/handlers"
	"webauth/totp"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

type ApplicationStatus struct {
	Status string `json:"status" example:"OK"`
}

func Health(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, ApplicationStatus{
		Status: "OK",
	})
}

func main() {

	u := totp.ProvisioningURI("bla", "bla", []byte("bla"))
	fmt.Printf("%v", u)
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:8080"},
		AllowMethods:     []string{"PUT", "PATCH", "POST", "DELETE", "GET"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Access-Control-Allow-Headers", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	router.GET("health", Health)

	router.POST("/register", handlers.RegisterUser)
	router.POST("/login", handlers.LoginUser)

	router.POST("/login/mfa", handlers.AuthMiddleware, handlers.GetSessions().Require(handlers.StagePending), handlers.VerifyLogin)
	router.GET("/self", handlers.AuthMiddleware, handlers.GetSessions().Require(handlers.StageFull), handlers.UserInfo)
	router.POST("/logout")
	mfa := router.Group("/mfa", handlers.AuthMiddleware, handlers.GetSessions().Require(handlers.StageFull))
	{
		mfa.POST("/enroll", handlers.EnableMfa)
		mfa.GET("/enroll/qr", handlers.MfaQr)
		mfa.POST("/enroll/confirm", handlers.ConfirmCode)
	}
	router.Run(":" + os.Getenv("PORT"))
}
