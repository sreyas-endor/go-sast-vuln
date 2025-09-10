package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSQLiVuln_StatusOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sqli/vuln", nil)
	q := url.Values{}
	q.Set("id", "1' OR '1'='1")
	req.URL.RawQuery = q.Encode()
	rec := httptest.NewRecorder()

	SQLiVuln(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestSQLiSafePrepared_StatusOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sqli/safe-prepared", nil)
	q := url.Values{}
	q.Set("id", "123")
	req.URL.RawQuery = q.Encode()
	rec := httptest.NewRecorder()

	SQLiSafePrepared(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestSQLiCrossFileFalsePositive_StatusOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sqli/crossfile", nil)
	q := url.Values{}
	q.Set("id", "abc")
	req.URL.RawQuery = q.Encode()
	rec := httptest.NewRecorder()

	SQLiCrossFileFalsePositive(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}
