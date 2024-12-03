package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type Client struct {
	iamClient *iam.Client
}

func New(ctx context.Context) (*Client, error) {
	awscfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load default AWS config: %w", err)
	}

	iamClient := iam.NewFromConfig(awscfg)
	return &Client{
		iamClient: iamClient,
	}, nil
}
