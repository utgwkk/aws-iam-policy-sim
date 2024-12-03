package awsclient

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/utgwkk/aws-iam-policy-sim/internal/slogx"
)

func (c *Client) ListRolePolicyDocuments(ctx context.Context, roleName string) ([]string, error) {
	// The maximum number of managed policies per IAM role is 20.
	// ref: https://docs.aws.amazon.com/singlesignon/latest/userguide/limits.html
	policyDocuments := make([]string, 0, 20)

	for listedPolicy, err := range c.iterateRoleAttachedManagedPolicies(ctx, roleName) {
		if err != nil {
			return nil, fmt.Errorf("failed to iterateRoleAttachedManagedPolicies: %w", err)
		}

		slog.DebugContext(ctx, "Invoking GetPolicy", slog.String("policyArn", *listedPolicy.PolicyArn))
		policy, err := c.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: listedPolicy.PolicyArn,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get policy: %w", err)
		}

		slog.DebugContext(ctx, "Invoking GetPolicyVersion", slog.String("policyName", *listedPolicy.PolicyName), slog.String("roleName", roleName))
		defaultVersionPolicy, err := c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: policy.Policy.Arn,
			VersionId: policy.Policy.DefaultVersionId,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get role policy: %w", err)
		}

		unescaped, err := unescapePolicyDocument(*defaultVersionPolicy.PolicyVersion.Document)
		if err != nil {
			return nil, fmt.Errorf("failed to unescape policy document: %w", err)
		}
		policyDocuments = append(policyDocuments, unescaped)
	}

	for policyName, err := range c.iterateRoleInlinePolicyNames(ctx, roleName) {
		if err != nil {
			return nil, fmt.Errorf("failed to iterateRoleInlinePolicyNames: %w", err)
		}

		slog.DebugContext(ctx, "Invoking GetRolePolicy", slog.String("policyName", policyName))
		policy, err := c.iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			PolicyName: aws.String(policyName),
			RoleName:   aws.String(roleName),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get policy: %w", err)
		}

		unescaped, err := unescapePolicyDocument(*policy.PolicyDocument)
		if err != nil {
			return nil, fmt.Errorf("failed to unescape policy document: %w", err)
		}
		policyDocuments = append(policyDocuments, unescaped)
	}

	return policyDocuments, nil
}

func (c *Client) iterateRoleAttachedManagedPolicies(ctx context.Context, roleName string) iter.Seq2[types.AttachedPolicy, error] {
	return func(yield func(types.AttachedPolicy, error) bool) {
		var marker *string
		for {
			slog.DebugContext(ctx, "Invoking ListAttachedRolePolicies", slog.String("roleName", roleName), slogx.StringPtr("marker", marker))
			res, err := c.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: aws.String(roleName),
				Marker:   marker,
			})
			if err != nil {
				yield(types.AttachedPolicy{}, err)
				return
			}
			slog.DebugContext(ctx, "ListAttachedRolePolicies", slog.Int("numAttachedPolicies", len(res.AttachedPolicies)))

			for _, policy := range res.AttachedPolicies {
				slog.DebugContext(ctx, "iterateRoleAttachedManagedPolicies loop", slog.String("policyName", *policy.PolicyName))
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

func (c *Client) iterateRoleInlinePolicyNames(ctx context.Context, roleName string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		var marker *string
		for {
			slog.DebugContext(ctx, "Invoking ListRolePolicies", slog.String("roleName", roleName), slogx.StringPtr("marker", marker))
			res, err := c.iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
				RoleName: aws.String(roleName),
				Marker:   marker,
			})
			if err != nil {
				yield("", err)
				return
			}
			slog.DebugContext(ctx, "ListRolePolicies", slog.Int("numPolicyNames", len(res.PolicyNames)))

			for _, policyName := range res.PolicyNames {
				slog.DebugContext(ctx, "iterateRoleInlinePolicyNames loop", slog.String("policyName", policyName))
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

func unescapePolicyDocument(policyDocument string) (string, error) {
	// A policy document obtained from GetRolePolicy or GetPolicyVersion is URL-encoded.
	//
	// refs:
	// - https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRolePolicy.html
	// - https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html
	unescaped, err := url.QueryUnescape(policyDocument)
	if err != nil {
		return "", fmt.Errorf("unescapePolicyDocument: %w", err)
	}
	return unescaped, nil
}
