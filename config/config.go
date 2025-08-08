package config

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"

	"example.com/models"
	"github.com/joho/godotenv"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"golang.org/x/crypto/bcrypt"
)

// constants definition
const (
	REQUEST_HEADER = "X-Request-ID"
)

type Config struct {
	DBUser         string
	DBPassword     string
	DBHost         string
	DBPort         string
	DBName         string
	ServerURL      string
	ServerPort     string
	APIURL         string
	JWTSecret      string
	CORSMaxAge     int
	SwaggerEnabled bool
	SwaggerPath    string
	DB             *bun.DB
}

func LoadConfig() (*Config, error) {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		// Log warning but don't fail - environment variables might be set directly
	}

	corsMaxAge, _ := strconv.Atoi(getEnv("CORS_MAX_AGE", "12"))
	swaggerEnabled, _ := strconv.ParseBool(getEnv("SWAGGER_ENABLED", "false"))

	config := &Config{
		DBUser:         getEnv("DB_USER", "postgres"),
		DBPassword:     getEnv("DB_PASSWORD", "postgres"),
		DBHost:         getEnv("DB_HOST", "localhost"),
		DBPort:         getEnv("DB_PORT", "5432"),
		DBName:         getEnv("DB_NAME", "starterkit"),
		ServerURL:      getEnv("SERVER_URL", "0.0.0.0"),
		ServerPort:     getEnv("SERVER_PORT", "8080"),
		APIURL:         getEnv("API_URL", "/api"),
		JWTSecret:      getEnv("JWT", "asteroidea"),
		CORSMaxAge:     corsMaxAge,
		SwaggerEnabled: swaggerEnabled,
		SwaggerPath:    getEnv("SWAGGER_PATH", "/docs"),
	}

	// Initialize database connection
	db, err := initDB(config)
	if err != nil {
		return nil, err
	}
	config.DB = db

	return config, nil
}

func (c *Config) GetDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName)
}

func (c *Config) GetPostgresDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=disable",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort)
}

func initDB(config *Config) (*bun.DB, error) {
	// First, try to create the database if it doesn't exist
	err := createDatabaseIfNotExists(config)
	if err != nil {
		return nil, err
	}

	// Now connect to the target database
	dsn := config.GetDSN()
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Run RBAC migration (creates new tables and migrates data)
	err = MigrateRBAC(db)
	if err != nil {
		return nil, err
	}

	// Create admin user if no users exist (now with role_id)
	err = createAdminUser(db)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func createDatabaseIfNotExists(config *Config) error {
	// Connect to the default postgres database
	postgresDSN := config.GetPostgresDSN()
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(postgresDSN)))
	defer sqldb.Close()

	// Check if database exists
	var exists bool
	row := sqldb.QueryRow("SELECT 1 FROM pg_database WHERE datname = $1", config.DBName)
	err := row.Scan(&exists)
	if err != nil && err.Error() != "sql: no rows in result set" {
		return err
	}

	// Create database if it doesn't exist
	if !exists {
		_, err = sqldb.Exec("CREATE DATABASE " + config.DBName)
		if err != nil {
			return err
		}
	}

	return nil
}

func createAdminUser(db *bun.DB) error {
	ctx := context.Background()

	// Check if any users exist
	count, err := db.NewSelect().Model((*models.User)(nil)).Count(ctx)
	if err != nil {
		return err
	}

	// If no users exist, create an admin user
	if count == 0 {
		// Get admin role
		var adminRole models.Role
		if err := db.NewSelect().Model(&adminRole).Where("name = ?", "admin").Scan(ctx); err != nil {
			return err
		}

		adminPassword := getEnv("ADMIN_PASSWORD", "admin123")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		adminUser := models.User{
			Username:    "admin",
			Name:        "System Administrator",
			Email:       "admin@asteroidea.com",
			Password:    string(hashedPassword),
			PhoneNumber: "",
			Status:      "active",
			RoleID:      adminRole.ID,
		}

		if _, err := db.NewInsert().Model(&adminUser).Exec(ctx); err != nil {
			return err
		}

		// Log admin user creation (you might want to use your logger here)
		// utils.Info().Msg("Admin user created with email: admin@asteroidea.com and password: " + adminPassword)
	}

	return nil
}
