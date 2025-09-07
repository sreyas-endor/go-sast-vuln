package handlers

import (
	"fmt"
	"net/http"

	demoDB "github.com/nitesh/go-sast-vuln/internal/db"
)

// SQLiVuln builds query with untrusted input
func SQLiVuln(w http.ResponseWriter, r *http.Request) {
	database, err := demoDB.New()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer database.Close()

	id := r.URL.Query().Get("id")
	// vulnerable string concatenation
	query := "SELECT * FROM users WHERE id = '" + id + "'"
	_, _ = database.Query(query)
	w.WriteHeader(http.StatusOK)
}

// SQLiSafePrepared uses prepared statement
func SQLiSafePrepared(w http.ResponseWriter, r *http.Request) {
	database, err := demoDB.New()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer database.Close()

	id := r.URL.Query().Get("id")
	_, _ = demoDB.SafeGetUserByID(database, id)
	w.WriteHeader(http.StatusOK)
}

// SQLiCrossFileFalsePositive: builds query here but validated elsewhere
// For single-file scanners, this will look dangerous; cross-file, it's safe.
func SQLiCrossFileFalsePositive(w http.ResponseWriter, r *http.Request) {
	database, err := demoDB.New()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer database.Close()

	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", sanitizeID(id))
	_, _ = demoDB.UnsafeQuery(database, query)
	w.WriteHeader(http.StatusOK)
}

// sanitizeID moved to sqli_sanitize.go to exercise multi-file analysis
