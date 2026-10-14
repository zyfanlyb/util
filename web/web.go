package web

import (
	"time"

	"github.com/gin-gonic/gin"
)

type ResponseVo struct {
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
	Page      *Page       `json:"page"`
}

func Success(ctx *gin.Context, data interface{}, page *Page) {
	ctx.JSON(200, ResponseVo{
		Code:      0,
		Message:   "success",
		Data:      data,
		Timestamp: time.Now().Unix(),
		Page:      page,
	})
}

func Error(ctx *gin.Context, message string) {
	ctx.JSON(200, ResponseVo{
		Code:      1,
		Message:   message,
		Timestamp: time.Now().Unix(),
		Page:      nil,
	})
}
