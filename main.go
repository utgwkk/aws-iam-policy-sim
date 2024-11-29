package main

import (
	"context"
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
)

var (
	argsTargetRoleName = flag.String("role-name", "", "IAM role name to simulate")
)

func main() {
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
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

		slog.DebugContext(ctx, "Invoking GetPolicyVersion", "policyName", listedPolicy, "targetRoleName", targetRoleName)
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

	for _, doc := range policyDocuments {
		slog.InfoContext(ctx, "policy documents", "doc", doc)
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
