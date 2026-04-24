package util

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func OK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok", "data": data})
}

func Fail(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"code": 1, "msg": msg, "data": nil})
	c.Abort()
}
