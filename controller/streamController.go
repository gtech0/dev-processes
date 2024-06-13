package controller

import (
	"dev-processes/dto"
	"dev-processes/initializer"
	"dev-processes/model"
	"dev-processes/service"
	"github.com/gin-gonic/gin"
	"math/rand"
	"net/http"
	"time"
)

type StreamController struct{}

func NewStreamController() *StreamController {
	return &StreamController{}
}

// CreateStream godoc
// @Security 	 Bearer
// @Summary      Create student stream
// @Description  create student stream
// @Produce      json
// @Success      200
// @Failure      400 {object} model.ErrorResponse
// @Failure      401 {object} model.ErrorResponse
// @Failure      403 {object} model.ErrorResponse
// @Failure      500 {object} model.ErrorResponse
// @Router       /stream/create [post]
func (s *StreamController) CreateStream(ctx *gin.Context) {
	body := dto.StreamDto{}

	if !service.IsCorrectRole(ctx, "Admin") {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized access",
		})
		return
	}

	if err := ctx.Bind(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	stream := model.Stream{
		Name: body.StreamName,
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
