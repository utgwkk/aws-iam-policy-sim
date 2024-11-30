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
	"github.com/utgwkk/aws-iam-policy-sim/input"
)

var (
	argsTargetRoleName = flag.String("role-name", "", "IAM role name to simulate")

	argsDebug = flag.String("debug", "", "Enable debug output if any non-empty string is passed")
)

func main() {
	flag.Parse()

	logLevel := slog.LevelInfo
	if *argsDebug != "" {
		logLevel = slog.LevelDebug
	}

	logHandler := tint.NewHandler(os.Stderr, &tint.Options{
		Level:      logLevel,
		TimeFormat: time.DateTime,
	})
	slog.SetDefault(slog.New(logHandler))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	targetRoleName := *argsTargetRoleName
	if targetRoleName == "" {
		logFatal(ctx, "-role-name is required")
	}

	awscfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		logFatal(ctx, "Failed to load default AWS config", "error", err)
	}

	simulateInput := &input.Input{}
	if err := json.NewDecoder(os.Stdin).Decode(&simulateInput); err != nil {
		logFatal(ctx, "Failed to read input from STDIN", "error", err)
	}
	slog.DebugContext(ctx, "Input decoded", "numSimulates", len(simulateInput.Statement))
	if len(simulateInput.Statement) == 0 {
		logFatal(ctx, "No simulates specified")
	}

	normalizedStmts := make([]*input.NormalizedStatement, len(simulateInput.Statement))
	for i, stmt := range simulateInput.Statement {
		normalized, err := stmt.Normalize()
		if err != nil {
			logFatal(ctx, "Error when normalizing input", "index", i, "error", err)
		}
		normalizedStmts[i] = normalized
	}

	iamClient := iam.NewFromConfig(awscfg)
	if err != nil {
		logFatal(ctx, "Failed to get role", "error", err)
	}

	policyDocuments, err := listRolePolicyDocuments(ctx, iamClient, targetRoleName)
	if err != nil {
		logFatal(ctx, "Failed to list role policy documents", "error", err)
	}

	if len(policyDocuments) == 0 {
		logFatal(ctx, "No policy is attached")
	}

	anyFailed := false
	for res, err := range simulateCustomPolicies(ctx, iamClient, normalizedStmts, policyDocuments) {
		action, resource := *res.EvalActionName, *res.EvalResourceName
		if err != nil {
			logFatal(ctx, "Failed to simulate custom policy", "error", err)
		}

		decisionType := res.EvalDecision
		switch decisionType {
		case types.PolicyEvaluationDecisionTypeAllowed:
			slog.InfoContext(ctx, "Allowed", "action", action, "resource", resource)
		case types.PolicyEvaluationDecisionTypeImplicitDeny:
			slog.ErrorContext(ctx, "Implicit deny", "action", action, "resource", resource)
			anyFailed = true
		case types.PolicyEvaluationDecisionTypeExplicitDeny:
			slog.ErrorContext(ctx, "Explicit deny", "action", action, "resource", resource)
			anyFailed = true
		default:
			slog.ErrorContext(ctx, "Unexpected decision type", "action", action, "resource", resource, "decisionType", decisionType)
			anyFailed = true
		}
	}

	if anyFailed {
		os.Exit(1)
	}
}
