package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"os/signal"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
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

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))

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
			logFatal(ctx, "Error on simulate", "index", i, "error", err)
		}
		normalizedStmts[i] = normalized
	}

	iamClient := iam.NewFromConfig(awscfg)
	if err != nil {
		logFatal(ctx, "Failed to get role", "error", err)
	}

	var policyDocuments []string
	for listedPolicy, err := range listAttachedRolePolicies(ctx, iamClient, targetRoleName) {
		if err != nil {
			logFatal(ctx, "Failed to list attached role policies", "error", err)
		}

		slog.DebugContext(ctx, "Invoking GetPolicy", "policyArn", *listedPolicy.PolicyArn)
		policy, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: listedPolicy.PolicyArn,
		})
		if err != nil {
			logFatal(ctx, "Failed to get policy", "error", err)
		}

		slog.DebugContext(ctx, "Invoking GetPolicyVersion", "policyName", *listedPolicy.PolicyName, "targetRoleName", targetRoleName)
		defaultVersionPolicy, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: policy.Policy.Arn,
			VersionId: policy.Policy.DefaultVersionId,
		})
		if err != nil {
			logFatal(ctx, "Failed to get role policy", "error", err)
		}

		unescaped, err := unescapePolicyDocument(*defaultVersionPolicy.PolicyVersion.Document)
		if err != nil {
			logFatal(ctx, "Failed to unescape policy document", "error", err)
		}
		policyDocuments = append(policyDocuments, unescaped)
	}

	for policyName, err := range listRolePolicyNames(ctx, iamClient, targetRoleName) {
		if err != nil {
			logFatal(ctx, "Failed to list attached role policies", "error", err)
		}

		slog.DebugContext(ctx, "Invoking GetRolePolicy", "policyName", policyName)
		policy, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			PolicyName: aws.String(policyName),
			RoleName:   aws.String(targetRoleName),
		})
		if err != nil {
			logFatal(ctx, "Failed to get policy", "error", err)
		}

		unescaped, err := unescapePolicyDocument(*policy.PolicyDocument)
		if err != nil {
			logFatal(ctx, "Failed to unescape policy document", "error", err)
		}
		policyDocuments = append(policyDocuments, unescaped)
	}

	if len(policyDocuments) == 0 {
		logFatal(ctx, "No policy is attached")
	}

	anyFailed := false
	for _, stmt := range normalizedStmts {
		for _, action := range stmt.Actions {
			for _, resource := range stmt.Resources {
				slog.DebugContext(ctx, "Invoking SimulateCustomPolicy", "action", action, "resource", resource)
				res, err := iamClient.SimulateCustomPolicy(ctx, &iam.SimulateCustomPolicyInput{
					ActionNames:     []string{action},
					PolicyInputList: policyDocuments,
					ResourceArns:    []string{resource},
				})
				if err != nil {
					logFatal(ctx, "Failed to simulate custom policy", "action", action, "resource", resource, "error", err)
				}

				decisionType := res.EvaluationResults[0].EvalDecision
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
		}
	}

	if anyFailed {
		os.Exit(1)
	}
}
