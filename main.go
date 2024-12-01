package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/lmittmann/tint"
	"github.com/utgwkk/aws-iam-policy-sim/internal/input"
	"github.com/utgwkk/aws-iam-policy-sim/internal/slogx"
)

var (
	argsTargetRoleName = flag.String("role-name", "", "IAM role name to simulate")

	argsDebug = flag.String("debug", "", "Enable debug output if any non-empty string is passed")
)

func main() {
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	logHandler := tint.NewHandler(os.Stderr, &tint.Options{
		Level:      slog.LevelInfo,
		TimeFormat: time.DateTime,
	})
	slog.SetDefault(slog.New(logHandler))

	if *argsDebug != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	targetRoleName := *argsTargetRoleName
	if targetRoleName == "" {
		slogx.FatalContext(ctx, "-role-name is required")
	}

	awscfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		slogx.FatalContext(ctx, "Failed to load default AWS config", slog.Any("error", err))
	}
	iamClient := iam.NewFromConfig(awscfg)

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

	policyDocuments, err := listRolePolicyDocuments(ctx, iamClient, targetRoleName)
	if err != nil {
		slogx.FatalContext(ctx, "Failed to list role policy documents", slog.Any("error", err))
	}

	if len(policyDocuments) == 0 {
		slogx.FatalContext(ctx, "No policy is attached")
	}

	anyFailed := false
	for res, err := range simulateCustomPolicies(ctx, iamClient, normalizedStmts, policyDocuments) {
		action, resource := *res.EvalActionName, *res.EvalResourceName
		if err != nil {
			slogx.FatalContext(ctx, "Failed to simulate custom policy", slog.Any("error", err))
		}

		decisionType := res.EvalDecision
		switch decisionType {
		case types.PolicyEvaluationDecisionTypeAllowed:
			slog.InfoContext(ctx, "Allowed", slog.String("action", action), slog.String("resource", resource))
		case types.PolicyEvaluationDecisionTypeImplicitDeny:
			slog.ErrorContext(ctx, "Implicit deny", slog.String("action", action), slog.String("resource", resource))
			anyFailed = true
		case types.PolicyEvaluationDecisionTypeExplicitDeny:
			slog.ErrorContext(ctx, "Explicit deny", slog.String("action", action), slog.String("resource", resource))
			anyFailed = true
		default:
			slog.ErrorContext(ctx, "Unexpected decision type", slog.String("action", action), slog.String("resource", resource), slog.Any("decisionType", decisionType))
			anyFailed = true
		}
	}

	if anyFailed {
		os.Exit(1)
	}
}
