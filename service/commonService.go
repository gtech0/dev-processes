package service

import (
	"dev-processes/database"
	"dev-processes/model"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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
		database.DB.First(&user, claims["sub"])
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

func IsCorrectRole(ctx *gin.Context, role model.Role) error {
	user, exists := ctx.Get("user")
	if !exists {
		return errors.New("user isn't found in context")
	}

	if user.(model.User).Role != role {
		return errors.New("unauthorized access")
	}

	return nil
}
