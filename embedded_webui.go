package main

import (
	"embed"
	"io/fs"
)

//go:embed webui/index.html webui/static/*
var embeddedWebUI embed.FS

func embeddedWebUIFS() fs.FS {
	sub, err := fs.Sub(embeddedWebUI, "webui")
	if err != nil {
		return nil
	}
	return sub
}

