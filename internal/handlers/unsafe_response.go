package handlers

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
)

// UnsafeEcho writes untrusted input directly to the response (vulnerable)
func UnsafeEcho(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	fmt.Fprintf(w, "Hello, %s", user)
}

// SafeEchoEscaped escapes untrusted input before writing
func SafeEchoEscaped(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	fmt.Fprintf(w, "Hello, %s", html.EscapeString(user))
}

// SafeEchoJSON marshals to JSON (sanitizer in rule)
func SafeEchoJSON(w http.ResponseWriter, r *http.Request) {
	payload := map[string]string{"user": r.URL.Query().Get("user")}
	_ = json.NewEncoder(w).Encode(payload)
}
