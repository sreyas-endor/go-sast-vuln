package handlers

import (
	"database/sql"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	echo "github.com/labstack/echo/v4"
)

// EchoSQLiVuln demonstrates SQLi-like sink with tainted input (not executing DB here)
func EchoSQLiVuln(c echo.Context) error {
	id := c.QueryParam("id")
	// vulnerable formatting of query string
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	_ = query
	return c.String(http.StatusOK, "ok")
}

// EchoPathTraversalVuln shows path usage from tainted param
func EchoPathTraversalVuln(c echo.Context) error {
	name := c.QueryParam("name")
	// vulnerable: use tainted value in os.Open sink
	_, _ = os.Open(name)
	return c.String(http.StatusOK, "ok")
}

// EchoPathTraversalSafe validates and cleans/joins safely
func EchoPathTraversalSafe(c echo.Context) error {
	name := c.QueryParam("name")
	if !fs.ValidPath(strings.TrimPrefix(name, "/")) {
		return c.String(http.StatusBadRequest, "bad path")
	}
	_ = filepath.Join("/safe", name)
	return c.String(http.StatusOK, "ok")
}

// EchoSQLiSafePrepared illustrates safe pattern (no real DB call here)
func EchoSQLiSafePrepared(c echo.Context) error {
	id := c.QueryParam("id")
	_ = id // would pass as parameter to prepared stmt
	return c.String(http.StatusOK, "ok")
}

// EchoSQLiDBVuln uses tainted input in DB query sink
func EchoSQLiDBVuln(c echo.Context) error {
	id := c.QueryParam("id")
	db, _ := sql.Open("sqlite3", ":memory:")
	defer db.Close()
	// vulnerable query concatenation
	q := "SELECT * FROM users WHERE id = '" + id + "'"
	_, _ = db.Query(q)
	return c.String(http.StatusOK, "ok")
}

// EchoXSSUnsafe writes unescaped user input
func EchoXSSUnsafe(c echo.Context) error {
	msg := c.QueryParam("msg")
	return c.String(http.StatusOK, msg)
}
