package handlers

import (
	"net/http"
	"net/url"

	"github.com/nitesh/go-sast-vuln/internal/utils"
)

// SSRFVuln builds a request from untrusted input directly (vulnerable)
func SSRFVuln(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	// vulnerable: direct use of user-supplied URL
	http.Get(raw) //nolint:errcheck
	w.WriteHeader(http.StatusOK)
}

// SSRFSafe validates target against allowlist and uses server-controlled base
func SSRFSafe(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	u, err := url.Parse(raw)
	if err != nil || !utils.IsAllowedHost(u) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	http.Get(u.String()) //nolint:errcheck
	w.WriteHeader(http.StatusOK)
}
