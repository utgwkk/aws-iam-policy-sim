package cli

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/utgwkk/aws-iam-policy-sim/internal/awsclient"
	"github.com/utgwkk/aws-iam-policy-sim/internal/input"
	"github.com/utgwkk/aws-iam-policy-sim/internal/slogx"
)

type CLI struct {
	RoleName string `required:"" help:"IAM role name to simulate" long:"role-name"`

	Debug bool `help:"Enable debug output" long:"debug"`
}

func (c *CLI) Do(ctx context.Context) {
	if c.Debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	targetRoleName := c.RoleName

	client, err := awsclient.New(ctx)
	if err != nil {
		slogx.FatalContext(ctx, "Failed to initialize client", slog.Any("error", err))
	}

	simulateInput := &input.Input{}
	slog.DebugContext(ctx, "Reading input from STDIN")
	if err := json.NewDecoder(os.Stdin).Decode(&simulateInput); err != nil {
		slogx.FatalContext(ctx, "Failed to read input from STDIN", slog.Any("error", err))
	}
	slog.DebugContext(ctx, "Input decoded", slog.Int("numSimulates", len(simulateInput.Statement)))
	if len(simulateInput.Statement) == 0 {
		slogx.FatalContext(ctx, "No simulates specified")
	}

	normalizedStmts := make([]*input.NormalizedStatement, len(simulateInput.Statement))
	for i, stmt := range simulateInput.Statement {
		normalized, err := stmt.Normalize()
		if err != nil {
			slogx.FatalContext(ctx, "Error when normalizing input", slog.Int("index", i), slog.Any("error", err))
		}
		normalizedStmts[i] = normalized
	}

	anyFailed, err := client.SimulateIAMRolePolicies(ctx, targetRoleName, normalizedStmts)
	if err != nil {
		slogx.FatalContext(ctx, "Failed to simulate", slog.Any("error", err))
	}

	if anyFailed {
		os.Exit(1)
	}
}
