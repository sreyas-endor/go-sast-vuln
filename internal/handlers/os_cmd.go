package handlers

import (
	"fmt"
	"net/http"
	"os/exec"
)

// OSCmdInjectionVuln passes user input to shell command
func OSCmdInjectionVuln(w http.ResponseWriter, r *http.Request) {
	img := r.URL.Query().Get("img")
	// vulnerable: using shell and -c with user-influenced command string
	exec.Command("sh", "-c", fmt.Sprintf("imagetool %s", img)).Run()
	w.WriteHeader(http.StatusOK)
}

// OSCmdInjectionSafe separates command and args, no shell
func OSCmdInjectionSafe(w http.ResponseWriter, r *http.Request) {
	img := r.URL.Query().Get("img")
	exec.Command("imagetool", img).Run()
	w.WriteHeader(http.StatusOK)
}

// DynamicExecCmd demonstrates non-static exec.Cmd usage (flagged)
func DynamicExecCmd(w http.ResponseWriter, r *http.Request) {
	bin := r.URL.Query().Get("bin")
	exec.Command(bin, "--version").Run()
	w.WriteHeader(http.StatusOK)
}
