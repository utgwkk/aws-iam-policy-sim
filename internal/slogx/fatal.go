package slogx

import (
	"context"
	"log/slog"
	"os"
)

// FatalContext is equivalent to ErrorContext followed by os.Exit(1).
func FatalContext(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
	os.Exit(1)
}
