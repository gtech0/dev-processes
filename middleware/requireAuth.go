package middleware

import (
	"dev-processes/database"
	"dev-processes/model"
	"dev-processes/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"time"
)

func RequireAuth(ctx *gin.Context) {
	tokenString, err := service.ExtractToken(ctx.GetHeader("Authorization"))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		var user model.User
		database.DB.Model(model.User{}).First(&user, claims["sub"])
		if user.ID == 0 {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "User not found",
			})
			return
		}

		var body model.Token
		err = database.DB.Where(&model.Token{Token: tokenString, UserID: user.ID}).First(&body).Error
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
			})
			return
		}

		if body.Revoked {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			body.Revoked = true
			err = database.DB.Save(&body).Error
			if err != nil {
				ctx.JSON(http.StatusBadRequest, gin.H{
					"error": err.Error(),
				})
				return
			}

			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		ctx.Set("user", user)
	} else {
		fmt.Println(err)
	}
	ctx.Next()
}
