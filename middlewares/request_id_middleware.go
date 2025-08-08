package middlewares

import (
	"crypto/rand"
	"encoding/hex"

	"example.com/config"
	"github.com/gin-gonic/gin"
)

func GenerateUniqueHex() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func RequestIDGeneratorMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		request_id := c.Request.Header.Get(config.REQUEST_HEADER)
		if request_id != "" {
			c.Next()
			return
		}
		id := GenerateUniqueHex()
		c.Request.Header.Set(config.REQUEST_HEADER, id)
		c.Header(config.REQUEST_HEADER, id)
		c.Next()
	}
}
