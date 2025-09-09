package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
)

// SQLiVuln builds query with untrusted input
func SQLiVuln(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite3", ":memory:")
	defer db.Close()

	id := r.URL.Query().Get("id")
	// vulnerable string concatenation
	query := "SELECT * FROM users WHERE id = '" + id + "'"
	_, _ = db.Query(query)
	w.WriteHeader(http.StatusOK)
}

// SQLiSafePrepared uses prepared statement
func SQLiSafePrepared(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite3", ":memory:")
	defer db.Close()

	id := r.URL.Query().Get("id")
	stmt, _ := db.Prepare("SELECT * FROM users WHERE id = ?")
	defer stmt.Close()
	_, _ = stmt.Query(id)
	w.WriteHeader(http.StatusOK)
}

// SQLiCrossFileFalsePositive: builds query here but validated elsewhere
// For single-file scanners, this will look dangerous; cross-file, it's safe.
func SQLiCrossFileFalsePositive(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite3", ":memory:")
	defer db.Close()

	id := r.URL.Query().Get("id")
	id = sanitizeID(id)

	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	_, _ = db.Query(query)
	w.WriteHeader(http.StatusOK)
}

// sanitizeID moved to sqli_sanitize.go to exercise multi-file analysis
