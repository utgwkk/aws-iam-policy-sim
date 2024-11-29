package main

import (
	"context"
	"iter"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

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
			slog.DebugContext(ctx, "ListRolePolicies", "numPolicyNames", len(res.PolicyNames))

			for _, policyName := range res.PolicyNames {
				slog.DebugContext(ctx, "listRolePolicyNames loop", "policyName", policyName)
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
