package handlers

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nitesh/go-sast-vuln/internal/utils"
)

const baseDir = "/tmp/safe-base"

// PathTraversalVuln demonstrates misuse of filepath.Clean as sanitization
func PathTraversalVuln(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	cleaned := filepath.Clean(name)
	b, _ := os.ReadFile(cleaned)
	_ = b
	w.WriteHeader(http.StatusOK)
}

// PathTraversalSafe uses safe join with base
func PathTraversalSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !fs.ValidPath(strings.TrimPrefix(name, "/")) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if p, ok := utils.SafeJoin(baseDir, name); ok {
		_, _ = os.ReadFile(p)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusBadRequest)
}
