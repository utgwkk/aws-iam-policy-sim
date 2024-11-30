package main

import (
	"fmt"
	"net/url"
)

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
