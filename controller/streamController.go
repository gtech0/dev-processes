package controller

import (
	"dev-processes/dto"
	"dev-processes/initializer"
	"dev-processes/model"
	"dev-processes/service"
	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v5"
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
// @Failure      401 {object} model.ErrorResponse
// @Failure      403 {object} model.ErrorResponse
// @Failure      500 {object} model.ErrorResponse
// @Router       /stream/create [post]
func (s *StreamController) CreateStream(ctx *gin.Context) {
	if !service.IsCorrectRole(ctx, model.Admin) {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized access",
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

	result := initializer.DB.Create(&stream)
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
// @Success      200 {array}  dto.StreamDto
// @Failure      400 {object} model.ErrorResponse
// @Failure      401 {object} model.ErrorResponse
// @Failure      403 {object} model.ErrorResponse
// @Failure      500 {object} model.ErrorResponse
// @Router       /stream/get [get]
func (s *StreamController) GetStreamNames(ctx *gin.Context) {
	if !service.IsCorrectRole(ctx, model.Admin) {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized access",
		})
		return
	}

	var streams []dto.StreamDto
	err := initializer.DB.Model(model.Stream{}).Order("created_at asc").Find(&streams).Error
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
// @Failure      401 {object} model.ErrorResponse
// @Failure      403 {object} model.ErrorResponse
// @Failure      500 {object} model.ErrorResponse
// @Router       /stream/create/{streamName} [post]
func (s *StreamController) CreateInviteCode(ctx *gin.Context) {
	if !service.IsCorrectRole(ctx, model.Admin) {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized access",
		})
		return
	}

	streamName := ctx.Param("streamName")
	var code dto.InviteCodeDto
	err := initializer.DB.Model(model.Stream{}).Where(&model.Stream{Name: streamName}).First(&code).Error
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
// @Failure      401 {object} model.ErrorResponse
// @Failure      403 {object} model.ErrorResponse
// @Failure      500 {object} model.ErrorResponse
// @Router       /stream/get/{code} [get]
func (s *StreamController) GetStreamByCode(ctx *gin.Context) {
	code := ctx.Param("code")

	var stream model.Stream
	err := initializer.DB.Model(model.Stream{}).Where(&model.Stream{Code: code}).First(&stream).Error
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
	}

	var streamDto dto.StreamGetDto
	streamDto.Name = stream.Name

	err = initializer.DB.Model(model.User{}).Where(&model.User{StreamName: null.StringFrom(stream.Name)}).Count(&streamDto.PeopleNum).Error
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
