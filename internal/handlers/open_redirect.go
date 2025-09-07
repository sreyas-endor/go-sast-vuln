package handlers

import (
	"net/http"
	"net/url"
	"strings"
)

// OpenRedirectVuln uses user-controlled URL directly
func OpenRedirectVuln(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	http.Redirect(w, r, target, http.StatusFound)
}

// OpenRedirectSafe validates against allowlist and uses relative paths for internal redirects
func OpenRedirectSafe(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" || strings.HasPrefix(target, "/") {
		http.Redirect(w, r, "/home", http.StatusFound)
		return
	}
	u, err := url.Parse(target)
	if err != nil {
		http.Redirect(w, r, "/error", http.StatusFound)
		return
	}
	allowed := map[string]struct{}{
		"trusted-domain.com": {},
		"example.com":        {},
	}
	if _, ok := allowed[u.Host]; ok && (u.Scheme == "https" || u.Scheme == "http") {
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/blocked", http.StatusFound)
}
