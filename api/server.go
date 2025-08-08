package api

import (
	"example.com/middlewares"
	"github.com/gin-gonic/gin"
)

type Server struct {
	Engine *gin.Engine
}

func NewServer() *Server {
	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	engine := gin.New()

	// Add middleware
	// Note: Removed gin.Logger() to avoid duplicate logs with our custom LoggerMiddleware
	engine.Use(gin.Recovery())
	engine.Use(middlewares.RequestIDGeneratorMiddleware())
	engine.Use(middlewares.LoggerMiddleware())

	return &Server{
		Engine: engine,
	}
}

func (s *Server) Run(port string) {
	if port == "" {
		port = "8080"
	}
	s.Engine.Run(":" + port)
}

func (s *Server) GetEngine() *gin.Engine {
	return s.Engine
}
