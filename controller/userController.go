package controller

import (
	"dev-processes/dto"
	"dev-processes/initializer"
	"dev-processes/model"
	"dev-processes/service"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"strconv"
	"time"
)

type UserController struct{}

func NewUserController() *UserController {
	return &UserController{}
}

// Signup godoc
// @Summary      Create account
// @Description  create user account
// @Accept       json
// @Produce      json
// @Param   	 payload body dto.UserDto false "Auth data"
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Router       /signup [post]
func (*UserController) Signup(ctx *gin.Context) {
	body := dto.UserDto{}

	if err := ctx.Bind(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if len(body.Login) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "login required",
		})
		return
	}

	if len(body.Password) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "password required",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	user := model.User{Login: body.Login, Password: string(hash)}
	result := initializer.DB.Create(&user)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	ctx.Status(http.StatusOK)
}

// Login godoc
// @Summary      Login
// @Description  login in account
// @Accept       json
// @Produce      json
// @Param   	 payload body dto.UserDto false "Auth data"
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Router       /login [post]
func (*UserController) Login(ctx *gin.Context) {
	body := dto.UserDto{}

	if err := ctx.Bind(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	var user model.User
	initializer.DB.Where(&model.User{Login: body.Login}).First(&user)

	if user.ID == 0 {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	err = revokeAllUserTokens(user.ID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	accessToken, err := createToken(user.ID, "ACCESS_TOKEN")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	refreshToken, err := createToken(user.ID, "REFRESH_TOKEN")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

// RefreshToken godoc
// @Summary      Refresh
// @Description  refresh token
// @Accept       json
// @Produce      json
// @Param   	 payload body dto.RefreshTokenDto false "Token"
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Router       /refresh [post]
func (*UserController) RefreshToken(ctx *gin.Context) {
	body := dto.RefreshTokenDto{}

	if err := ctx.Bind(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	service.ValidateRefreshToken(ctx, body.RefreshToken)

	user, exists := ctx.Get("user")
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found in context",
		})
		return
	}

	err := revokeAllUserTokens(user.(model.User).ID)
	accessToken, err := createToken(user.(model.User).ID, "ACCESS_TOKEN")
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: body.RefreshToken,
	})
}

// Logout godoc
// @Security 	 ApiKeyAuth
// @Summary      Logout
// @Description  logout
// @Accept       json
// @Produce      json
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Failure      401 {object} model.ErrorResponse
// @Failure      500 {object} model.ErrorResponse
// @Router       /logout [post]
func (u *UserController) Logout(ctx *gin.Context) {
	tokenString, err := service.ExtractToken(ctx.GetHeader("Authorization"))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
	}

	initializer.DB.Model(model.Token{}).Where(model.Token{Token: tokenString}).Updates(model.Token{Revoked: true})
}

// ChangePassword godoc
// @Security 	 ApiKeyAuth
// @Summary      Change password
// @Description  change your password
// @Accept       json
// @Produce      json
// @Param   	 payload body dto.PasswordDto false "New password"
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Router       /password [patch]
func (u *UserController) ChangePassword(ctx *gin.Context) {
	user, exists := ctx.Get("user")
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found in context",
		})
		return
	}

	body := dto.PasswordDto{}

	if err := ctx.Bind(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if len(body.NewPassword) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "password required",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), 10)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err = initializer.DB.Model(model.User{}).Where(user.(model.User).ID).Updates(model.User{Password: string(hash)}).Error
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
}

func createToken(userId uint, tokenType string) (string, error) {
	tokenTime, err := strconv.Atoi(os.Getenv(tokenType))
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userId,
		"exp": time.Now().Add(time.Second * time.Duration(tokenTime)).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", errors.New("failed to create token")
	}

	if tokenType == "REFRESH_TOKEN" {
		return tokenString, nil
	}

	if err = initializer.DB.Save(&model.Token{
		UserID:  userId,
		Token:   tokenString,
		Revoked: false,
	}).Error; err != nil {
		return "", err
	}

	return tokenString, nil
}

func revokeAllUserTokens(userId uint) error {
	err := initializer.DB.Model(model.Token{}).Where(&model.Token{UserID: userId}).Updates(model.Token{Revoked: true}).Error
	if err != nil {
		return err
	}
	return nil
}
