package main

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func userHandlerFixed(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT email FROM users WHERE name = $1", name)
	if err == nil {
		rows.Close()
	}
}

func pingHandlerFixed(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, _ := exec.Command("ping", "-c", "1", "--", host).Output()
	w.Write(out)
}

func fileHandlerFixed(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	w.Write(data)
}

func helloHandlerFixed(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))
}
