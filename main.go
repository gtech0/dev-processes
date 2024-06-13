package main

import (
	"dev-processes/controller"
	_ "dev-processes/docs"
	"dev-processes/initializer"
	"dev-processes/middleware"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"log"
)

func init() {
	initializer.LoadEnv()
	initializer.ConnectToDB()
	initializer.SyncDatabase()
}

// @title           User API
// @version         0.01
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8001
// @BasePath  /api

// @securityDefinitions.apikey Bearer
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// @externalDocs.description  OpenAPI
// @externalDocs.url          https://swagger.io/resources/open-api/
func main() {
	router := gin.Default()
	router.Use(cors.Default())

	userController := controller.NewUserController()
	streamController := controller.NewStreamController()
	user := router.Group("/api/user")
	{
		user.POST("/signup", userController.Signup)
		user.POST("/login", userController.Login)
		user.POST("/refresh", userController.RefreshToken)
		user.POST("/logout", middleware.RequireAuth, userController.Logout)
		user.PATCH("/password", middleware.RequireAuth, userController.ChangePassword)
	}

	stream := router.Group("/api/stream")
	{
		stream.POST("/create", middleware.RequireAuth, streamController.CreateStream)
		stream.GET("/get", middleware.RequireAuth, streamController.GetStreamNames)
	}

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	if err := router.Run(); err != nil {
		log.Fatal(err)
	}
}
