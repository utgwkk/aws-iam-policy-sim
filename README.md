# aws-iam-policy-sim

A simple IAM Policy Simulator CLI

## Installation

```console
$ go install github.com/utgwkk/aws-iam-policy-sim@latest
```

## Usage

First, prepare JSON like below (NOTE: you can use IAM policy document JSON directly!)

```json
{
  "Statement": [
    {
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:GetObjectTagging",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket/*"
      ]
    },
    {
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::example-bucket"
    }
  ]
}
```

Then, execute `aws-iam-policy-sim`.

```console
$ aws-iam-policy-sim --role-name example-role < path/to/statement.json
2024-12-03 08:22:00 INF Allowed level=INFO msg=Allowed action=s3:PutObject resource=arn:aws:s3:::example-bucket/*
2024-12-03 08:22:00 INF Allowed level=INFO msg=Allowed action=s3:GetObject resource=arn:aws:s3:::example-bucket/*
2024-12-03 08:22:00 INF Allowed level=INFO msg=Allowed action=s3:GetObjectTagging resource=arn:aws:s3:::example-bucket/*
2024-12-03 08:22:00 INF Allowed level=INFO msg=Allowed action=s3:DeleteObject resource=arn:aws:s3:::example-bucket/*
2024-12-03 08:22:00 INF Allowed level=INFO msg=Allowed action=s3:ListBucket resource=arn:aws:s3:::example-bucket
```

If your IAM role lacks some permission, `aws-iam-policy-sim` reports an error.

```console
$ aws-iam-policy-sim --role-name example-role < path/to/statement.json
2024-12-03 08:22:00 INF msg=Allowed action=s3:PutObject resource=arn:aws:s3:::example-bucket/*
2024-12-03 08:22:00 INF msg=Allowed action=s3:GetObject resource=arn:aws:s3:::example-bucket/*
2024-12-03 08:22:00 INF msg=Allowed action=s3:GetObjectTagging resource=arn:aws:s3:::example-bucket/*
2024-12-03 08:22:00 INF msg=Allowed action=s3:DeleteObject resource=arn:aws:s3:::example-bucket/*
2024-12-03 08:22:00 ERR msg="Implicit deny" action=s3:ListBucket resource=arn:aws:s3:::example-bucket
```

## Limitations

- `aws-iam-policy-sim` only supports a simulation for IAM Roles. Simulations for IAM Users or Groups are not supported now.
