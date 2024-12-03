package awsclient

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/utgwkk/aws-iam-policy-sim/internal/input"
	"github.com/utgwkk/aws-iam-policy-sim/internal/slogx"
)

func (c *Client) SimulateIAMRolePolicies(ctx context.Context, roleName string, normalizedStmts []*input.NormalizedStatement) (bool, error) {
	policyDocuments, err := c.ListRolePolicyDocuments(ctx, roleName)
	if err != nil {
		return false, fmt.Errorf("failed to list role policy documents: %w", err)
	}

	if len(policyDocuments) == 0 {
		return false, errors.New("no policy is attached")
	}

	anyFailed := false
	for res, err := range c.simulateCustomPolicies(ctx, normalizedStmts, policyDocuments) {
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
	return anyFailed, nil
}

func (c *Client) simulateCustomPolicies(ctx context.Context, normalizedStmts []*input.NormalizedStatement, policyDocuments []string) iter.Seq2[types.EvaluationResult, error] {
	return func(yield func(types.EvaluationResult, error) bool) {
		for _, stmt := range normalizedStmts {
			for _, action := range stmt.Actions {
				for _, resource := range stmt.Resources {
					for res, err := range c.simulateCustomPolicy(ctx, policyDocuments, action, resource) {
						if !yield(res, err) {
							return
						}
					}
				}
			}
		}
	}
}

func (c *Client) simulateCustomPolicy(ctx context.Context, policyDocuments []string, action, resource string) iter.Seq2[types.EvaluationResult, error] {
	return func(yield func(types.EvaluationResult, error) bool) {
		var marker *string
		for {
			slog.DebugContext(ctx, "Invoking SimulateCustomPolicy", slog.String("action", action), slog.String("resource", resource), slogx.StringPtr("marker", marker))
			res, err := c.iamClient.SimulateCustomPolicy(ctx, &iam.SimulateCustomPolicyInput{
				ActionNames:     []string{action},
				PolicyInputList: policyDocuments,
				ResourceArns:    []string{resource},
				Marker:          marker,
			})
			if err != nil {
				yield(types.EvaluationResult{}, nil)
				return
			}

			for _, result := range res.EvaluationResults {
				if !yield(result, nil) {
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
