package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
)

// SQLiVuln builds query with untrusted input
func SQLiVuln(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err == nil && db != nil {
		defer db.Close()
	}

	id := r.URL.Query().Get("id")
	if db != nil {
		stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
		if err == nil && stmt != nil {
			defer stmt.Close()
			_, _ = stmt.Query(id)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// SQLiSafePrepared uses prepared statement
func SQLiSafePrepared(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err == nil && db != nil {
		defer db.Close()
	}

	id := r.URL.Query().Get("id")
	if db != nil {
		stmt, _ := db.Prepare("SELECT * FROM users WHERE id = ?")
		if stmt != nil {
			defer stmt.Close()
			_, _ = stmt.Query(id)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// SQLiCrossFileFalsePositive: builds query here but validated elsewhere
// For single-file scanners, this will look dangerous; cross-file, it's safe.
func SQLiCrossFileFalsePositive(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err == nil && db != nil {
		defer db.Close()
	}

	id := r.URL.Query().Get("id")
	id = sanitizeID(id)

	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	if db != nil {
		_, _ = db.Query(query)
	}
	w.WriteHeader(http.StatusOK)
}

// sanitizeID moved to sqli_sanitize.go to exercise multi-file analysis
