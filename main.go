package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/alecthomas/kong"
	"github.com/lmittmann/tint"
	"github.com/utgwkk/aws-iam-policy-sim/internal/cli"
	"github.com/utgwkk/aws-iam-policy-sim/internal/slogx"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	logHandler := tint.NewHandler(os.Stderr, &tint.Options{
		Level:      slog.LevelInfo,
		TimeFormat: time.DateTime,
	})
	slog.SetDefault(slog.New(logHandler))

	var cli cli.CLI
	parser, err := kong.New(&cli)
	if err != nil {
		slogx.FatalContext(ctx, "failed to initialize kong parser", slog.Any("error", err))
	}
	if _, err := parser.Parse(os.Args[1:]); err != nil {
		slogx.FatalContext(ctx, "failed to parse args", slog.Any("error", err))
	}

	cli.Do(ctx)
}
