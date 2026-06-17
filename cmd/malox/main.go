package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"malox/internal/app"
)

var (
	version   = "unknown"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := app.Run(ctx, app.Options{
		Args:   os.Args[1:],
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Build: app.BuildInfo{
			Version:   version,
			Commit:    commit,
			BuildDate: buildDate,
		},
	})
	os.Exit(code)
}
