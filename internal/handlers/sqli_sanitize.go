package handlers

// sanitizeID lives in another file to require multi-file analysis
func sanitizeID(id string) string {
	// primitive allowlist: only digits allowed; otherwise fallback to 0
	for _, ch := range id {
		if ch < '0' || ch > '9' {
			return "0"
		}
	}
	return id
}
