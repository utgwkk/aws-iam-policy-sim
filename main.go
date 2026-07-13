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
	"github.com/utgwkk/slogerr"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	logHandler := tint.NewTextHandler(os.Stderr, &tint.Options{
		Level:      slog.LevelInfo,
		TimeFormat: time.DateTime,
	})
	slog.SetDefault(slog.New(logHandler))

	var cli cli.CLI
	parser, err := kong.New(&cli)
	if err != nil {
		slogx.FatalContext(ctx, "failed to initialize kong parser", slogerr.Error(err))
	}
	if _, err := parser.Parse(os.Args[1:]); err != nil {
		slogx.FatalContext(ctx, "failed to parse args", slogerr.Error(err))
	}

	cli.Do(ctx)
}
