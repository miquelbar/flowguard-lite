package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var assetsFS embed.FS

// Handler returns an http.Handler serving the embedded SPA static assets.
func Handler() http.Handler {
	subFS, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		// Panic on initialization error if embed syntax fails (should never happen under Go build verification)
		panic(err)
	}
	return http.FileServer(http.FS(subFS))
}
