// Package web embeds the built frontend (web/dist) into the Go binary.
//
// dist/ is produced by `npm run build` and is not committed, except for a
// placeholder that keeps `go build` working on a fresh clone. Without a build,
// the server answers with a message explaining how to build the UI.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built UI, rooted at its index.html.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // "dist" is embedded above, so this cannot happen
	}
	return sub
}
