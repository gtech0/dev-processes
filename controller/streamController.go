package controller

import (
	"dev-processes/database"
	"dev-processes/dto"
	"dev-processes/model"
	"dev-processes/service"
	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v5"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"net/http"
	"time"
)

type StreamController struct{}

func NewStreamController() *StreamController {
	return &StreamController{}
}

// CreateStream godoc
// @Tags         Stream
// @Security 	 Bearer
// @Summary      Create student stream
// @Description  create student stream
// @Produce      json
// @Param   	 payload body dto.StreamDto false "stream name"
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Router       /stream/create [post]
func (s *StreamController) CreateStream(ctx *gin.Context) {
	if err := service.IsCorrectRole(ctx, model.Admin); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	body := dto.StreamDto{}
	if err := ctx.Bind(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	stream := model.Stream{
		Name: body.Name,
		Code: generateRandString(),
	}

	result := database.DB.Create(&stream)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create stream " + stream.Name,
		})
		return
	}

	ctx.Status(http.StatusOK)
}

// GetStreamNames godoc
// @Tags         Stream
// @Security 	 Bearer
// @Summary      Get stream names
// @Description  get stream names sorted by creation date
// @Produce      json
// @Success      200 {array}  string
// @Failure      400 {object} model.ErrorResponse
// @Router       /stream/get [get]
func (s *StreamController) GetStreamNames(ctx *gin.Context) {
	if err := service.IsCorrectRole(ctx, model.Admin); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	var streams []string
	err := database.DB.Model(model.Stream{}).Order("created_at asc").Select("name").Find(&streams).Error
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	ctx.JSON(http.StatusOK, streams)
}

// CreateInviteCode godoc
// @Tags         Stream
// @Security 	 Bearer
// @Summary      Create invite code
// @Description  create invite code
// @Produce      json
// @Param        streamName path int true "Stream name"
// @Success      200 {object} dto.InviteCodeDto
// @Failure      400 {object} model.ErrorResponse
// @Router       /stream/create/{streamName} [post]
func (s *StreamController) CreateInviteCode(ctx *gin.Context) {
	if err := service.IsCorrectRole(ctx, model.Admin); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	streamName := ctx.Param("streamName")
	var code dto.InviteCodeDto
	err := database.DB.Model(model.Stream{}).Where(&model.Stream{Name: streamName}).First(&code).Error
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	ctx.JSON(http.StatusOK, code)
}

// GetStreamByCode godoc
// @Tags         Stream
// @Security 	 Bearer
// @Summary      Get stream with invite code
// @Description  get stream using invite code
// @Produce      json
// @Param        code path int true "Invite code"
// @Success      200 {object} dto.StreamGetDto
// @Failure      400 {object} model.ErrorResponse
// @Router       /stream/get/{code} [get]
func (s *StreamController) GetStreamByCode(ctx *gin.Context) {
	code := ctx.Param("code")

	var stream model.Stream
	err := database.DB.Model(model.Stream{}).Where(&model.Stream{Code: code}).First(&stream).Error
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	var streamDto dto.StreamGetDto
	streamDto.Name = stream.Name

	err = database.DB.Model(model.User{}).Where(&model.User{StreamName: null.StringFrom(stream.Name)}).Count(&streamDto.PeopleNum).Error
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	ctx.JSON(http.StatusOK, streamDto)
}

func generateRandString() string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	rangeStart := 8
	rangeEnd := 10
	offset := rangeEnd - rangeStart
	randLength := seededRand.Intn(offset) + rangeStart

	charset := "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ0123456789"

	b := make([]byte, randLength)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset)-1)]
	}

	return string(b)
}

// RegisterUserInStream godoc
// @Tags         Stream
// @Summary      Create student account
// @Description  create student account
// @Accept       json
// @Produce      json
// @Param        code path int true "Invite code"
// @Param   	 payload body dto.UserDto false "Registration data"
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Router       /stream/register/{code} [post]
func (*StreamController) RegisterUserInStream(ctx *gin.Context) {
	body := dto.StudentDto{}

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

	code := ctx.Param("code")

	var streamName string
	err = database.DB.Model(model.Stream{}).Where(&model.Stream{Code: code}).Select("name").First(&streamName).Error
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	user := model.User{
		Name:        body.Name,
		Surname:     body.Surname,
		Login:       body.Login,
		Password:    string(hash),
		Role:        model.Student,
		Deactivated: false,
		StreamName:  null.StringFrom(streamName),
		Comment:     null.StringFromPtr(nil),
	}

	result := database.DB.Create(&user)
	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	ctx.Status(http.StatusOK)
}

// DeleteStudentFromStream godoc
// @Tags         Stream
// @Summary      Delete student from stream
// @Description  delete student from stream
// @Accept       json
// @Produce      json
// @Param        code path int true "Invite code"
// @Param   	 payload body []string false "Student ids"
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Router       /stream/delete/{code} [post]
func (*StreamController) DeleteStudentFromStream(ctx *gin.Context) {
	if err := service.IsCorrectRole(ctx, model.Admin); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	var body []string
	if err := ctx.Bind(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	code := ctx.Param("code")
	var streamName string
	err := database.DB.Model(model.Stream{}).Where(&model.Stream{Code: code}).Select("name").First(&streamName).Error
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if err = database.DB.Model(model.User{}).
		Where("stream_name = ? AND id IN ?", streamName, body).
		Update("stream_name", null.StringFromPtr(nil)).Error; err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx.Status(http.StatusOK)
}

// LeaveStream godoc
// @Tags         Stream
// @Summary      Leave from stream
// @Description  student can leave from stream
// @Accept       json
// @Produce      json
// @Param        streamName path int true "Stream name"
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Router       /stream/leave/{streamName} [post]
func (*StreamController) LeaveStream(ctx *gin.Context) {
	if err := service.IsCorrectRole(ctx, model.Student); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		return
	}

	userCtx, exists := ctx.Get("user")
	if !exists {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found in context",
		})
		return
	}

	streamName := ctx.Param("streamName")

	var stream model.Stream
	if err := database.DB.Model(model.Stream{}).Where("name = ?", streamName).First(&stream).Error; err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if database.DB.Model(model.User{}).
		Where("stream_name = ? AND id = ?", streamName, userCtx.(model.User).ID).
		Update("stream_name", null.StringFromPtr(nil)).RowsAffected == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found in this stream",
		})
		return
	}

	ctx.Status(http.StatusOK)
}
