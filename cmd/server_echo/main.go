package main

import (
	"log"

	echo "github.com/labstack/echo/v4"
	"github.com/nitesh/go-sast-vuln/internal/handlers"
)

func main() {
	e := echo.New()
	e.GET("/echo/sqli/vuln", handlers.EchoSQLiVuln)
	e.GET("/echo/sqli/safe", handlers.EchoSQLiSafePrepared)
	e.GET("/echo/sqli/db-vuln", handlers.EchoSQLiDBVuln)
	e.GET("/echo/path/vuln", handlers.EchoPathTraversalVuln)
	e.GET("/echo/path/safe", handlers.EchoPathTraversalSafe)
	e.GET("/echo/xss/unsafe", handlers.EchoXSSUnsafe)
	log.Fatal(e.Start(":8082"))
}
