package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nztzsh/go-sast-vuln/internal/handlers"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Unsafe response endpoints
	mux.HandleFunc("/xss/unsafe", handlers.UnsafeEcho)
	mux.HandleFunc("/xss/safe-escaped", handlers.SafeEchoEscaped)
	mux.HandleFunc("/xss/safe-json", handlers.SafeEchoJSON)

	// Open redirect endpoints
	mux.HandleFunc("/redirect/vuln", handlers.OpenRedirectVuln)
	mux.HandleFunc("/redirect/safe", handlers.OpenRedirectSafe)

	// SSRF endpoints
	mux.HandleFunc("/ssrf/vuln", handlers.SSRFVuln)
	mux.HandleFunc("/ssrf/safe", handlers.SSRFSafe)

	// SQL injection endpoints
	mux.HandleFunc("/sqli/vuln", handlers.SQLiVuln)
	mux.HandleFunc("/sqli/safe-prepared", handlers.SQLiSafePrepared)
	mux.HandleFunc("/sqli/crossfile", handlers.SQLiCrossFileFalsePositive)

	// OS command injection and dynamic exec endpoints
	mux.HandleFunc("/os/vuln", handlers.OSCmdInjectionVuln)
	mux.HandleFunc("/os/safe", handlers.OSCmdInjectionSafe)
	mux.HandleFunc("/os/dynamic", handlers.DynamicExecCmd)

	// Path traversal endpoints
	mux.HandleFunc("/path/vuln", handlers.PathTraversalVuln)
	mux.HandleFunc("/path/safe", handlers.PathTraversalSafe)

	// Cookie flag endpoints
	mux.HandleFunc("/cookie/missing", handlers.CookieMissingFlags)
	mux.HandleFunc("/cookie/safe", handlers.CookieHttpOnlySecure)

	// Weak hash endpoints
	mux.HandleFunc("/hash/weak-md5", handlers.WeakHashMD5)
	mux.HandleFunc("/hash/strong-sha256", handlers.StrongHashSHA256)

	// CGI import sample
	mux.HandleFunc("/cgi/import", handlers.CGIImportHandler)

	// Intentionally missing ReadTimeout/ReadHeaderTimeout (slowloris vulnerable server)
	// A safe server variant will be provided under a different binary.
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadTimeout:       1e9, // 1 second
		ReadHeaderTimeout: 1e9, // 1 second
	}

	log.Printf("listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

	_ = time.Second // keep time import for later safe server sample
}
