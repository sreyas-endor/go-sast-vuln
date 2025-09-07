package db

import (
	"database/sql"
)

// New creates a demo in-memory DB.
func New() (*sql.DB, error) {
	// No driver import needed to compile; at runtime this will error, which is fine for SAST samples
	return sql.Open("sqlite3", ":memory:")
}

// UnsafeQuery executes a raw query string directly (for demo only).
func UnsafeQuery(database *sql.DB, query string) (*sql.Rows, error) {
	return database.Query(query)
}

// SafeGetUserByID uses a prepared statement to avoid SQL injection.
func SafeGetUserByID(database *sql.DB, id string) (*sql.Rows, error) {
	stmt, err := database.Prepare("SELECT * FROM users WHERE id = ?")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	return stmt.Query(id)
}
