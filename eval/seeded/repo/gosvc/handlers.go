package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

func userHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query(fmt.Sprintf("SELECT email FROM users WHERE name = '%s'", name))
	if err == nil {
		rows.Close()
	}
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	w.Write(data)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

func main() {
	http.HandleFunc("/user", userHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/file", fileHandler)
	http.HandleFunc("/hello", helloHandler)
	http.ListenAndServe(":8080", nil)
}
