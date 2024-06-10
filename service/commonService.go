package service

import (
	"dev-processes/initializer"
	"dev-processes/model"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"strings"
	"time"
)

func ValidateRefreshToken(ctx *gin.Context, tokenString string) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		panic(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		var user model.User
		initializer.DB.First(&user, claims["sub"])
		if user.ID == 0 {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Token expired",
			})
			return
		}

		ctx.Set("user", user)
	} else {
		fmt.Println(err)
	}
}

func ExtractToken(header string) (string, error) {
	token := strings.Split(header, " ")
	if len(token) != 2 {
		return "", errors.New("token format error")
	}

	return token[1], nil
}
