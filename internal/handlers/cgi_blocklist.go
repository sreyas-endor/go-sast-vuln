package handlers

import (
	"net/http"
	_ "net/http/cgi"
)

// CGIImportHandler exists to keep the import referenced
func CGIImportHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
