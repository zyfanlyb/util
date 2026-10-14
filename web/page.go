package web

import "github.com/gin-gonic/gin"
import "strconv"

type Page struct {
	PageNum  int `json:"pageNum" form:"pageNum"`
	PageSize int `json:"pageSize" form:"pageSize"`
	Total    int64 `json:"total" form:"total"`
}

func GetRequestPage(ctx *gin.Context) (page Page) {
	var err error
	page.PageNum, err = strconv.Atoi(ctx.Query("pageNum"))
	if err != nil || page.PageNum <= 0 {
		page.PageNum = 1
	}
	page.PageSize, err = strconv.Atoi(ctx.Query("pageSize"))
	if err != nil || page.PageSize <= 0 || page.PageSize > 20 {
		page.PageSize = 20
	}
	return
}