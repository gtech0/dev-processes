package main

import (
	"dev-processes/controller"
	"dev-processes/initializer"
	"dev-processes/middleware"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"log"
)

func init() {
	initializer.LoadEnv()
	initializer.ConnectToDB()
	initializer.SyncDatabase()
}

func main() {
	router := gin.Default()
	router.Use(cors.Default())

	userController := controller.NewUserController()
	api := router.Group("/api")
	api.POST("/signup", userController.Signup)
	api.POST("/login", userController.Login)
	api.POST("/refresh", userController.RefreshToken)
	api.POST("/logout", middleware.RequireAuth, userController.Logout)
	api.PATCH("/password", middleware.RequireAuth, userController.ChangePassword)

	if err := router.Run(); err != nil {
		log.Fatal(err)
	}
}
