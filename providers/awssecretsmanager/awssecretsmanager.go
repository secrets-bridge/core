// Package awssecretsmanager implements providers.Provider against AWS
// Secrets Manager using AWS SDK for Go v2.
//
// Auth: the default AWS SDK credential chain (env, shared profile, IRSA,
// IMDS). When running on EKS with an IRSA-annotated ServiceAccount the
// chain finds the projected OIDC token automatically. Pass a roleArn in
// the config to AssumeRole into another account after the default chain
// completes.
//
// Metadata vs. value split:
//   - GetMetadata calls DescribeSecret — no value is ever read.
//   - ListMetadata pages through ListSecrets and returns one
//     SecretMetadata per entry without touching values.
//   - GetValue calls GetSecretValue — only the agent should invoke this.
//   - PutValue calls PutSecretValue, falling back to CreateSecret when
//     the secret does not yet exist.
//
// Notes:
//   - DescribeSecret does not expose a content checksum, so the Checksum
//     field on SecretMetadata is left empty here; the agent computes it
//     after GetValue and surfaces it to the Control Plane separately.
//   - LabelSelector matching in ListMetadata is not yet implemented;
//     the request returns every secret in scope.
package awssecretsmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/secrets-bridge/core/providers"
)

// Kind is the canonical provider name used during Registry lookups.
const Kind = "aws-sm"

// Config keys recognised by New.
const (
	ConfigRegion   = "region"
	ConfigRoleArn  = "roleArn"
	ConfigEndpoint = "endpoint"
)

// Register wires the AWS Secrets Manager factory into r under Kind.
// Call this from main during startup; the package does NOT register
// itself via init() to keep global state out of test binaries.
func Register(r *providers.Registry) {
	r.Register(Kind, New)
}

// awsSMClient is the small slice of the SDK client used by Provider.
// Defining the interface here lets unit tests inject a fake without
// pulling in the full SDK surface.
type awsSMClient interface {
	DescribeSecret(ctx context.Context, in *secretsmanager.DescribeSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(ctx context.Context, in *secretsmanager.PutSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	CreateSecret(ctx context.Context, in *secretsmanager.CreateSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
}

// New constructs a Provider backed by the real AWS SDK client. The
// returned value satisfies providers.Provider.
func New(ctx context.Context, cfg providers.Config) (providers.Provider, error) {
	region, _ := cfg[ConfigRegion].(string)
	if region == "" {
		return nil, errors.New("awssecretsmanager: config.region is required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("awssecretsmanager: load default config: %w", err)
	}

	if arn, _ := cfg[ConfigRoleArn].(string); arn != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		creds := stscreds.NewAssumeRoleProvider(stsClient, arn, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "secrets-bridge"
		})
		awsCfg.Credentials = awsv2.NewCredentialsCache(creds)
	}

	smOpts := []func(*secretsmanager.Options){}
	if ep, _ := cfg[ConfigEndpoint].(string); ep != "" {
		smOpts = append(smOpts, func(o *secretsmanager.Options) {
			o.BaseEndpoint = awsv2.String(ep)
		})
	}

	return &Provider{client: secretsmanager.NewFromConfig(awsCfg, smOpts...)}, nil
}

// Provider is an AWS Secrets Manager backend speaking the
// metadata/value-split providers.Provider interface.
type Provider struct {
	client awsSMClient
}

// GetMetadata returns descriptive metadata without reading the value.
// Backed by DescribeSecret.
func (p *Provider) GetMetadata(ctx context.Context, ref providers.SecretRef) (providers.SecretMetadata, error) {
	out, err := p.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: awsv2.String(ref.Name),
	})
	if err != nil {
		if isNotFound(err) {
			return providers.SecretMetadata{}, fmt.Errorf("%w: %s", providers.ErrNotFound, ref)
		}
		return providers.SecretMetadata{}, fmt.Errorf("awssecretsmanager: describe %s: %w", ref.Name, err)
	}
	return providers.SecretMetadata{
		Ref:       ref,
		Version:   versionFromDescribe(out),
		Labels:    tagsToLabels(out.Tags),
		CreatedAt: derefTime(out.CreatedDate),
		UpdatedAt: derefTime(out.LastChangedDate),
		// Checksum is intentionally empty: DescribeSecret does not
		// expose a content hash. The agent populates this after
		// GetValue when it needs to drive diff/conflict logic.
	}, nil
}

// ListMetadata enumerates secrets in the requested scope and returns
// one SecretMetadata per entry. Pagination is handled internally — the
// returned slice is fully materialized.
//
// LabelSelector matching is not yet implemented; every secret in scope
// is returned regardless of scope.LabelSelector.
func (p *Provider) ListMetadata(ctx context.Context, scope providers.ProviderScope) ([]providers.SecretMetadata, error) {
	var out []providers.SecretMetadata
	var token *string
	for {
		page, err := p.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
			MaxResults: awsv2.Int32(100),
			NextToken:  token,
		})
		if err != nil {
			return nil, fmt.Errorf("awssecretsmanager: list secrets: %w", err)
		}
		for _, s := range page.SecretList {
			if s.Name == nil {
				continue
			}
			out = append(out, providers.SecretMetadata{
				Ref: providers.SecretRef{
					Provider: Kind,
					Scope:    scope.Scope,
					Name:     *s.Name,
				},
				Labels:    tagsToLabels(s.Tags),
				CreatedAt: derefTime(s.CreatedDate),
				UpdatedAt: derefTime(s.LastChangedDate),
			})
		}
		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		token = page.NextToken
	}
	return out, nil
}

// GetValue reads the secret payload. This is the only method on the
// Provider that touches the value; callers MUST NOT log the returned
// SecretValue.Bytes.
func (p *Provider) GetValue(ctx context.Context, ref providers.SecretRef) (providers.SecretValue, error) {
	in := &secretsmanager.GetSecretValueInput{SecretId: awsv2.String(ref.Name)}
	if ref.Version != "" {
		in.VersionId = awsv2.String(ref.Version)
	}
	out, err := p.client.GetSecretValue(ctx, in)
	if err != nil {
		if isNotFound(err) {
			return providers.SecretValue{}, fmt.Errorf("%w: %s", providers.ErrNotFound, ref)
		}
		return providers.SecretValue{}, fmt.Errorf("awssecretsmanager: get %s: %w", ref.Name, err)
	}
	v := providers.SecretValue{ContentType: "application/octet-stream"}
	switch {
	case out.SecretString != nil:
		v.Bytes = []byte(*out.SecretString)
		v.ContentType = "text/plain"
	case out.SecretBinary != nil:
		v.Bytes = out.SecretBinary
	}
	return v, nil
}

// PutValue writes a new secret version. If the secret does not exist
// yet, PutSecretValue returns ResourceNotFoundException and PutValue
// falls back to CreateSecret. Both paths return the resulting version.
func (p *Provider) PutValue(ctx context.Context, ref providers.SecretRef, value providers.SecretValue, opts providers.PutOptions) (providers.SecretVersion, error) {
	putIn := &secretsmanager.PutSecretValueInput{
		SecretId:     awsv2.String(ref.Name),
		SecretBinary: value.Bytes,
	}
	if opts.IfMatch != "" {
		putIn.ClientRequestToken = awsv2.String(opts.IfMatch)
	}
	putOut, err := p.client.PutSecretValue(ctx, putIn)
	if err == nil {
		return providers.SecretVersion{
			ID:        derefString(putOut.VersionId),
			CreatedAt: time.Now().UTC(),
		}, nil
	}
	if !isNotFound(err) {
		return providers.SecretVersion{}, fmt.Errorf("awssecretsmanager: put %s: %w", ref.Name, err)
	}

	createIn := &secretsmanager.CreateSecretInput{
		Name:         awsv2.String(ref.Name),
		SecretBinary: value.Bytes,
		Description:  awsv2.String("Managed by secrets-bridge"),
		Tags:         labelsToTags(opts.Labels),
	}
	createOut, err := p.client.CreateSecret(ctx, createIn)
	if err != nil {
		return providers.SecretVersion{}, fmt.Errorf("awssecretsmanager: create %s: %w", ref.Name, err)
	}
	return providers.SecretVersion{
		ID:        derefString(createOut.VersionId),
		CreatedAt: time.Now().UTC(),
	}, nil
}

// versionFromDescribe pulls the currently-active version ID out of a
// DescribeSecret response. AWS returns version stages as a map from
// version ID to stage list ("AWSCURRENT" / "AWSPREVIOUS" / custom).
func versionFromDescribe(out *secretsmanager.DescribeSecretOutput) providers.SecretVersion {
	for id, stages := range out.VersionIdsToStages {
		for _, s := range stages {
			if s == "AWSCURRENT" {
				return providers.SecretVersion{
					ID:        id,
					CreatedAt: derefTime(out.LastChangedDate),
				}
			}
		}
	}
	return providers.SecretVersion{}
}

func tagsToLabels(tags []smtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			out[*t.Key] = *t.Value
		}
	}
	return out
}

func labelsToTags(labels map[string]string) []smtypes.Tag {
	if len(labels) == 0 {
		return nil
	}
	out := make([]smtypes.Tag, 0, len(labels))
	for k, v := range labels {
		out = append(out, smtypes.Tag{Key: awsv2.String(k), Value: awsv2.String(v)})
	}
	return out
}

func isNotFound(err error) bool {
	var nf *smtypes.ResourceNotFoundException
	return errors.As(err, &nf)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
