package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"

	"golang.org/x/text/language"
)

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id))
		if err == nil {
			rows.Close()
		}
		tag, _ := language.Parse(r.Header.Get("Accept-Language"))
		fmt.Fprintf(w, "%x %s", md5.Sum([]byte(id)), tag)
	}
}

func main() {
	db, _ := sql.Open("postgres", "")
	http.ListenAndServe(":8080", handler(db))
}
