package main

import (
	"fmt"
	"net/http"
)

// CASE-001: Multiple auth-related issues in the same file
func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Weak password comparison
	if password == "admin123" {
		fmt.Fprintln(w, "welcome")
	}

	// Another auth issue: direct token comparison
	token := r.Header.Get("Authorization")
	if token == "secret-token" {
		fmt.Fprintln(w, "authorized")
	}

	// Session manipulation
	session.Set("user", username)

	// Credentials usage
	credentials.Validate(username, password)
}

// CASE-003: Multiple injection vectors in same handler
func searchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
	query := fmt.Sprintf("SELECT * FROM products WHERE name = '%s'", q)
	fmt.Println(query)

	cmd := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", q)
	fmt.Println(cmd)

	update := fmt.Sprintf("UPDATE products SET views = views + 1 WHERE id = '%s'", q)
	fmt.Println(update)
}

// CASE-004: Multiple config drift issues
func setupServer() {
	// TODO: fix config for production
	// hardcoded port number
	http.ListenAndServe(":8080", nil)

	// Another hardcoded value
	// FIXME: move config to environment
}
