package middlewares

import (
	"strings"
	"time"

	"example.com/utils"
	"github.com/gin-gonic/gin"
)

// isBrowserUserAgent checks if the user agent is from a common browser
func isBrowserUserAgent(userAgent string) bool {
	browserIdentifiers := []string{
		"Mozilla/", "Chrome/", "Safari/", "Firefox/", "Edge/", "Opera/",
	}

	for _, identifier := range browserIdentifiers {
		if strings.Contains(userAgent, identifier) {
			return true
		}
	}
	return false
}

// shouldSkipLogging determines if we should skip logging for certain requests
func shouldSkipLogging(method, path string, statusCode int) bool {
	// Skip OPTIONS requests (CORS preflight)
	if method == "OPTIONS" {
		return true
	}

	// Skip health check requests
	if path == "/health" {
		return true
	}

	// Skip static file requests with 200/304 status
	if statusCode == 200 || statusCode == 304 {
		staticPaths := []string{"/favicon.ico", "/robots.txt", "/sitemap.xml"}
		for _, staticPath := range staticPaths {
			if path == staticPath {
				return true
			}
		}
	}

	return false
}

// LoggerMiddleware provides structured logging for HTTP requests
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency and other metrics
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		// Log the request with cleaner format
		logger := utils.Info()

		// Add status code with color/level indication
		if statusCode >= 400 {
			logger = utils.Warn() // Use warning level for 4xx/5xx errors
		}

		logger = logger.
			Str("method", method).
			Str("path", path).
			Int("status", statusCode).
			Str("ip", clientIP).
			Dur("latency", latency)

		// Only log user agent for non-browser requests or API calls
		userAgent := c.Request.UserAgent()
		if userAgent != "" && !isBrowserUserAgent(userAgent) {
			logger = logger.Str("user_agent", userAgent)
		}

		// Skip logging for common uninteresting requests
		if shouldSkipLogging(method, path, statusCode) {
			return
		}

		logger.Msgf("%s %s - %d", method, path, statusCode)
	}
}
