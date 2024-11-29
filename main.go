package main

import (
	"context"
	"encoding/json"
	"flag"
	"iter"
	"log/slog"
	"net/url"
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
		slog.ErrorContext(ctx, "-role-name is required")
		os.Exit(1)
	}

	awscfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to load default AWS config", "error", err)
		os.Exit(1)
	}

	simulateInput := &input.Input{}
	if err := json.NewDecoder(os.Stdin).Decode(&simulateInput); err != nil {
		slog.ErrorContext(ctx, "Failed to read input from STDIN", "error", err)
		os.Exit(1)
	}
	slog.DebugContext(ctx, "input decoded", "numSimulates", len(simulateInput.Simulates))
	if len(simulateInput.Simulates) == 0 {
		slog.ErrorContext(ctx, "No simulates specified")
		os.Exit(1)
	}

	normalizedSimulates := make([]*input.NormalizedSimulate, len(simulateInput.Simulates))
	for i, simulate := range simulateInput.Simulates {
		normalized, err := simulate.Normalize()
		if err != nil {
			slog.ErrorContext(ctx, "Error on simulate", "index", i, "error", err)
			os.Exit(1)
		}
		normalizedSimulates[i] = normalized
	}

	iamClient := iam.NewFromConfig(awscfg)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get role", "error", err)
		os.Exit(1)
	}

	var policyDocuments []string
	for listedPolicy, err := range listAttachedRolePolicies(ctx, iamClient, targetRoleName) {
		if err != nil {
			slog.ErrorContext(ctx, "Failed to list attached role policies", "error", err)
			os.Exit(1)
		}

		slog.DebugContext(ctx, "Invoking GetPolicy", "PolicyArn", *listedPolicy.PolicyArn)
		policy, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: listedPolicy.PolicyArn,
		})
		if err != nil {
			slog.ErrorContext(ctx, "Failed to get policy", "error", err)
			os.Exit(1)
		}

		slog.DebugContext(ctx, "Invoking GetPolicyVersion", "policyName", *listedPolicy.PolicyName, "targetRoleName", targetRoleName)
		defaultVersionPolicy, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: policy.Policy.Arn,
			VersionId: policy.Policy.DefaultVersionId,
		})
		if err != nil {
			slog.ErrorContext(ctx, "Failed to get role policy", "error", err)
			os.Exit(1)
		}

		unescaped, err := url.QueryUnescape(*defaultVersionPolicy.PolicyVersion.Document)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to unescape policy document", "error", err)
			os.Exit(1)
		}
		policyDocuments = append(policyDocuments, unescaped)
	}

	for policyName, err := range listRolePolicyNames(ctx, iamClient, targetRoleName) {
		if err != nil {
			slog.ErrorContext(ctx, "Failed to list attached role policies", "error", err)
			os.Exit(1)
		}

		slog.DebugContext(ctx, "Invoking GetPolicy", "policyName", policyName)
		policy, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			PolicyName: aws.String(policyName),
			RoleName:   aws.String(targetRoleName),
		})
		if err != nil {
			slog.ErrorContext(ctx, "Failed to get policy", "error", err)
			os.Exit(1)
		}

		unescaped, err := url.QueryUnescape(*policy.PolicyDocument)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to unescape policy document", "error", err)
			os.Exit(1)
		}
		policyDocuments = append(policyDocuments, unescaped)
	}

	if len(policyDocuments) == 0 {
		slog.ErrorContext(ctx, "No policy is attached")
		os.Exit(1)
	}

	anyFailed := false
	for _, simulate := range normalizedSimulates {
		for _, action := range simulate.Actions {
			for _, resource := range simulate.Resources {
				slog.DebugContext(ctx, "Invoking SimulateCustomPolicy", "action", action, "resource", resource)
				res, err := iamClient.SimulateCustomPolicy(ctx, &iam.SimulateCustomPolicyInput{
					ActionNames:     []string{action},
					PolicyInputList: policyDocuments,
					ResourceArns:    []string{resource},
				})
				if err != nil {
					slog.ErrorContext(ctx, "Failed to simulate custom policy", "action", action, "resource", resource, "error", err)
					os.Exit(1)
				}

				decisionType := res.EvaluationResults[0].EvalDecision
				switch decisionType {
				case types.PolicyEvaluationDecisionTypeAllowed:
					slog.InfoContext(ctx, "allowed", "action", action, "resource", resource)
				case types.PolicyEvaluationDecisionTypeImplicitDeny:
					slog.ErrorContext(ctx, "inplicit deny", "action", action, "resource", resource)
					anyFailed = true
				case types.PolicyEvaluationDecisionTypeExplicitDeny:
					slog.ErrorContext(ctx, "explicit deny", "action", action, "resource", resource)
					anyFailed = true
				default:
					slog.ErrorContext(ctx, "unexpected decision type", "action", action, "resource", resource, "decisionType", decisionType)
					anyFailed = true
				}
			}
		}
	}

	if anyFailed {
		os.Exit(1)
	}
}

func listAttachedRolePolicies(ctx context.Context, iamClient *iam.Client, roleName string) iter.Seq2[types.AttachedPolicy, error] {
	return func(yield func(types.AttachedPolicy, error) bool) {
		var marker *string
		for {
			slog.DebugContext(ctx, "Invoking ListAttachedRolePolicies", "roleName", roleName)
			res, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: aws.String(roleName),
				Marker:   marker,
			})
			if err != nil {
				yield(types.AttachedPolicy{}, err)
				return
			}
			slog.DebugContext(ctx, "ListAttachedRolePolicies", "numAttachedPolicies", len(res.AttachedPolicies))

			for _, policy := range res.AttachedPolicies {
				slog.DebugContext(ctx, "listRolePolices loop", "policyName", *policy.PolicyName)
				if !yield(policy, nil) {
					return
				}
			}
			if !res.IsTruncated {
				return
			}
			marker = res.Marker
		}
	}
}

func listRolePolicyNames(ctx context.Context, iamClient *iam.Client, roleName string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		var marker *string
		for {
			slog.DebugContext(ctx, "Invoking ListRolePolicies", "roleName", roleName)
			res, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
				RoleName: aws.String(roleName),
				Marker:   marker,
			})
			if err != nil {
				yield("", err)
				return
			}
			slog.DebugContext(ctx, "ListAttachedRolePolicies", "numPolicyNames", len(res.PolicyNames))

			for _, policyName := range res.PolicyNames {
				slog.DebugContext(ctx, "listRolePolices loop", "policyName", policyName)
				if !yield(policyName, nil) {
					return
				}
			}
			if !res.IsTruncated {
				return
			}
			marker = res.Marker
		}
	}
}
