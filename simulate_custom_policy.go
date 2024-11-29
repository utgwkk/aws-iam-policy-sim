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
					for res, err := range simulateCustomPolicy(ctx, iamClient, policyDocuments, action, resource) {
						if !yield(res, err) {
							return
						}
					}
				}
			}
		}
	}
}

func simulateCustomPolicy(ctx context.Context, iamClient *iam.Client, policyDocuments []string, action, resource string) iter.Seq2[types.EvaluationResult, error] {
	return func(yield func(types.EvaluationResult, error) bool) {
		var marker *string
		for {
			slog.DebugContext(ctx, "Invoking SimulateCustomPolicy", "action", action, "resource", resource)
			res, err := iamClient.SimulateCustomPolicy(ctx, &iam.SimulateCustomPolicyInput{
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
