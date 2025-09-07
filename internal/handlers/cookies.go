package handlers

import (
	"net/http"
)

// CookieMissingFlags sets cookie without HttpOnly and Secure (vulnerable)
func CookieMissingFlags(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Set-Cookie", "session=abc123; Path=/")
	w.WriteHeader(http.StatusOK)
}

// CookieHttpOnlySecure sets both flags (safe)
func CookieHttpOnlySecure(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "abc123",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})
	w.WriteHeader(http.StatusOK)
}
