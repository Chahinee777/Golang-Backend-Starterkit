package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// @Description API response wrapper
type Response struct {
	Message string      `json:"message,omitempty" ` // use it when we need to display in front
	Data    interface{} `json:"data,omitempty"`
	Code    string      `json:"code,omitempty" ` // error like ERR_USER_NOT_FOUND
	Error   string      `json:"error,omitempty" `
}

func Success(c *gin.Context, status int, message string, data interface{}) {
	c.JSON(status, Response{
		Message: message,
		Data:    data,
	})
}

func HttpError(c *gin.Context, status int, code string, message string, err string) {
	c.JSON(status, Response{
		Code:    code,
		Message: message,
		Error:   err,
	})
}

// Common responses
func BadRequest(c *gin.Context, code string, message string, err string) {
	HttpError(c, http.StatusBadRequest, code, message, err)
}

func NotFound(c *gin.Context, code string, message string, err string) {
	HttpError(c, http.StatusNotFound, code, message, err)
}

func InternalError(c *gin.Context, code string, message string, err string) {
	HttpError(c, http.StatusInternalServerError, code, message, err)
}

func Created(c *gin.Context, data interface{}) {
	Success(c, http.StatusCreated, "Created successfully", data)
}

func OK(c *gin.Context, data interface{}) {
	Success(c, http.StatusOK, "Success", data)
}
