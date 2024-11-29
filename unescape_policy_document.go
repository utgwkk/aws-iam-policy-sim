package main

import (
	"fmt"
	"net/url"
)

func unescapePolicyDocument(policyDocument string) (string, error) {
	unescaped, err := url.QueryUnescape(policyDocument)
	if err != nil {
		return "", fmt.Errorf("unescapePolicyDocument: %w", err)
	}
	return unescaped, nil
}
