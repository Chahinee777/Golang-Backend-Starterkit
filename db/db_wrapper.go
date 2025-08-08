package db

import (
	"errors"
	"log"

	"github.com/uptrace/bun"
)

// DBWrapper encapsulates the Bun DB instance.
type DBWrapper struct {
	DB *bun.DB
}

// NewDatabaseConnection initializes the database based on the given `dbType`.
// Currently supports "postgres".
func NewDatabaseConnection(dbType string, dsn string) (*DBWrapper, error) {
	switch dbType {
	case "postgres":
		return PostgresDB(dsn, 5)
	default:
		return nil, errors.New("unsupported database type")
	}
}

// Close closes the database connection.
func (wrapper *DBWrapper) Close() {
	if wrapper.DB != nil {
		log.Println("Closing database connection")
		wrapper.DB.Close()
	}
}
