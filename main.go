package main

import (
	"log"
	"os"
	"time"

	"example.com/api"
	"example.com/config"
	_ "example.com/docs" // Import for swagger docs
	"example.com/routes"
	"example.com/utils"
	"github.com/rs/zerolog"
)

// @title Asteroidea Starter Kit API
// @version 1.0
// @description A simple authentication API built with Go and Gin
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func setupLogging() {
	// Configure zerolog to use a human-friendly console writer
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Create console writer with custom formatting
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}

	// Set the global logger
	logger := zerolog.New(consoleWriter).With().Timestamp().Logger()
	zerolog.DefaultContextLogger = &logger
}

func main() {
	// Setup improved logging
	setupLogging()

	utils.Info().Msg("Initializing Asteroidea Starter Kit API...")

	// Load configuration
	config, err := config.LoadConfig()
	if err != nil {
		utils.Error().Err(err).Msg("Failed to load config")
		log.Fatal("Failed to load config:", err)
	}

	// Initialize server
	server := api.NewServer()
	engine := server.GetEngine()

	// Setup routes
	routes.SetupRoutes(engine, config)

	// Start server
	utils.Info().Msgf("Starting server on %s:%s", config.ServerURL, config.ServerPort)
	utils.Info().Msgf("API available at: http://%s:%s%s", config.ServerURL, config.ServerPort, config.APIURL)
	if config.SwaggerEnabled {
		utils.Info().Msgf("Swagger docs available at: http://%s:%s%s", config.ServerURL, config.ServerPort, config.SwaggerPath)
	}
	utils.Info().Msg("Database connected and migrations completed")
	utils.Info().Msg("If this is the first run, admin user has been created:")
	utils.Info().Msg("  Email: admin@asteroidea.com")
	utils.Info().Msg("  Password: Check ADMIN_PASSWORD in .env file (default: admin123)")

	server.Run(config.ServerPort)
}
