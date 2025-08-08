package utils

import (
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	REQUEST_HEADER = "X-Request-ID"
)

// Initialize the logger with console writer
func init() {
	// Configure zerolog to use a human-friendly console writer
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	})
}

func Trace(context ...*gin.Context) *zerolog.Event {
	return getLogger("TRACE", context...)
}

func Debug(context ...*gin.Context) *zerolog.Event {
	return getLogger("DEBUG", context...)
}

func Warn(context ...*gin.Context) *zerolog.Event {
	return getLogger("WARN", context...)
}

func Info(context ...*gin.Context) *zerolog.Event {
	return getLogger("INFO", context...)
}

func Error(context ...*gin.Context) *zerolog.Event {
	return getLogger("ERROR", context...)
}

func SetLoggerLevel(logLevel string) {
	level := zerolog.InfoLevel
	switch strings.ToUpper(logLevel) {
	case "TRACE":
		level = zerolog.TraceLevel
	case "DEBUG":
		level = zerolog.DebugLevel
	case "INFO":
		level = zerolog.InfoLevel
	case "WARN":
		level = zerolog.WarnLevel
	case "ERROR":
		level = zerolog.ErrorLevel
	default:
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
}

func getRequestID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	return c.Request.Header.Get(REQUEST_HEADER)
}

func getLogger(level string, context ...*gin.Context) *zerolog.Event {
	var logger *zerolog.Event
	switch strings.ToUpper(level) {
	case "TRACE":
		logger = log.Trace()
	case "DEBUG":
		logger = log.Debug()
	case "WARN":
		logger = log.Warn()
	case "INFO":
		logger = log.Info()
	case "ERROR":
		logger = log.Error()
	default:
		logger = log.Info()
	}

	if len(context) == 0 {
		return logger
	}

	c := context[0]
	requestID := getRequestID(c)
	if requestID != "" {
		return logger.Str("request_id", requestID)
	}

	return logger
}
