package main

import (
	"context"
	"iter"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/utgwkk/aws-iam-policy-sim/input"
)

func simulateCustomPolicies(ctx context.Context, iamClient *iam.Client, normalizedStmts []*input.NormalizedStatement, policyDocuments []string) iter.Seq2[types.EvaluationResult, error] {
	return func(yield func(types.EvaluationResult, error) bool) {
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
						yield(types.EvaluationResult{}, nil)
						return
					}

					for _, result := range res.EvaluationResults {
						if !yield(result, nil) {
							return
						}
					}
				}
			}
		}
	}
}
