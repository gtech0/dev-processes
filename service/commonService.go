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

func ValidateRefreshToken(ctx *gin.Context, tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		var user model.User
		initializer.DB.First(&user, claims["sub"])
		if user.ID == 0 {
			return errors.New("user not found")
		}

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return errors.New("token is expired")
		}

		ctx.Set("user", user)
	} else {
		return err
	}

	return nil
}

func ExtractToken(header string) (string, error) {
	token := strings.Split(header, " ")
	if len(token) != 2 {
		return "", errors.New("token format error")
	}

	return token[1], nil
}

func IsCorrectRole(ctx *gin.Context, role string) bool {
	user, exists := ctx.Get("user")
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found in context",
		})
		return false
	}

	if user.(model.User).Role != role {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized access",
		})
		return false
	}
	return true
}
