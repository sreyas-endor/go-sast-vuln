package handlers

import (
	"crypto/md5"
	"crypto/sha256"
	"net/http"
)

// WeakHashMD5 demonstrates a weak hash usage
func WeakHashMD5(w http.ResponseWriter, r *http.Request) {
	data := []byte(r.URL.Query().Get("data"))
	_ = md5.Sum(data)
	w.WriteHeader(http.StatusOK)
}

// StrongHashSHA256 demonstrates a safer alternative
func StrongHashSHA256(w http.ResponseWriter, r *http.Request) {
	data := []byte(r.URL.Query().Get("data"))
	_ = sha256.Sum256(data)
	w.WriteHeader(http.StatusOK)
}
