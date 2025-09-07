package utils

import (
	"net/url"
	"path/filepath"
	"strings"
)

// IsAllowedHost returns true if the host is in the allowlist.
func IsAllowedHost(u *url.URL) bool {
	if u == nil {
		return false
	}
	allowed := map[string]struct{}{
		"api.trusted.com":    {},
		"trusted-domain.com": {},
		"example.com":        {},
	}
	_, ok := allowed[u.Host]
	return ok && (u.Scheme == "https" || u.Scheme == "http")
}

// SafeJoin ensures that rel stays within base using absolute path + prefix check.
func SafeJoin(base, rel string) (string, bool) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", false
	}
	absPath, err := filepath.Abs(filepath.Join(absBase, rel))
	if err != nil {
		return "", false
	}
	if !strings.HasPrefix(absPath, absBase) {
		return "", false
	}
	return absPath, true
}
