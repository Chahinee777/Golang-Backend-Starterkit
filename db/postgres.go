package db

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// // DBWrapper encapsulates the Bun DB instance and additional utilities.
// type DBWrapper struct {
// 	DB *bun.DB
// }

// NewPostgresDB initializes a PostgreSQL connection with retry logic and best practices.
func PostgresDB(dsn string, maxRetries int) (*DBWrapper, error) {
	// var err error
	var db *bun.DB
	// Retry logic for connection
	for i := 0; i < maxRetries; i++ {
		// dsn := "postgres://postgres:@localhost:5432?sslmode=disable"

		// sqldb := sql.OpenDB(dsn)
		sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
		db = bun.NewDB(sqldb, pgdialect.New())

		// Configure connection pool
		db.SetMaxOpenConns(30)
		db.SetMaxIdleConns(10)
		db.SetConnMaxLifetime(time.Hour)

		// log.Printf("Failed to connect to PostgreSQL (attempt %d/%d): %v", i+1, maxRetries, err)
		// time.Sleep(time.Second * 2) // Wait before retrying
		// Test connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			return nil, err
		} else {
			i = 6
		}

	}

	// if err != nil {
	// 	return nil, err // Return the error if all retries fail
	// }

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	log.Println("Successfully connected to PostgreSQL")

	return &DBWrapper{DB: db}, nil
}

// // Close gracefully shuts down the database connection pool.
// func (wrapper *DBWrapper) Close() {
// 	if wrapper.DB != nil {
// 		log.Println("Closing database connection")
// 		wrapper.DB.Close()
// 	}
// }
