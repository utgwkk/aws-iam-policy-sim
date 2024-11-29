package main

import (
	"context"
	"log/slog"
	"os"
)

func logFatal(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
	os.Exit(1)
}
