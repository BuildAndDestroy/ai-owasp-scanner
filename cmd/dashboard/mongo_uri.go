package main

import (
	"net/url"
	"os"
	"strings"
)

// resolveMongoURI picks a connection string in this order:
// 1) MONGODB_URI (full URI, optional override)
// 2) Built from MONGO_ROOT_USERNAME, MONGO_ROOT_PASSWORD, and MONGO_HOST (default 127.0.0.1:27017)
// 3) Unauthenticated default for local dev
func resolveMongoURI() string {
	if v := strings.TrimSpace(os.Getenv("MONGODB_URI")); v != "" {
		return v
	}
	user := strings.TrimSpace(os.Getenv("MONGO_ROOT_USERNAME"))
	pass := os.Getenv("MONGO_ROOT_PASSWORD")
	if user == "" || pass == "" {
		return "mongodb://127.0.0.1:27017"
	}
	host := getenv("MONGO_HOST", "127.0.0.1:27017")
	u := &url.URL{
		Scheme: "mongodb",
		User:   url.UserPassword(user, pass),
		Host:   host,
		Path:   "/",
	}
	q := make(url.Values)
	q.Set("authSource", "admin")
	u.RawQuery = q.Encode()
	return u.String()
}
