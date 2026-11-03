// Package web holds the site files compiled into the binary.
package web

import "embed"

// Public is served as is; nothing outside this list is reachable over HTTP.
//
//go:embed index.html robots.txt js style *.png *.jpg
var Public embed.FS

// Pages are rendered only through handlers that check the session.
//
//go:embed admin.html login.html
var Pages embed.FS
