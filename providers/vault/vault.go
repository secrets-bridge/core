// Package vault implements providers.Provider against HashiCorp Vault
// KV v2.
//
// Auth modes:
//   - kubernetes: uses the projected service account token to log in
//     via the Kubernetes auth method. Token lease tracked and refreshed
//     before expiry so long-running agents don't fall over.
//   - token: takes a static Vault token. Intended for local dev.
//
// Metadata vs. value split:
//   - GetMetadata reads {kvMount}/metadata/{...} — never the value.
//   - ListMetadata walks the metadata tree, returning one
//     SecretMetadata per leaf without reading any value.
//   - GetValue reads {kvMount}/data/{...} — only the agent should
//     invoke this.
//   - PutValue writes {kvMount}/data/{...} with the KV v2 envelope.
//
// Notes:
//   - The Checksum field on SecretMetadata stays empty here; the KV v2
//     metadata endpoint does not expose a content hash. The agent
//     computes it after GetValue.
//   - LabelSelector matching against custom_metadata is not yet
//     implemented; ListMetadata returns every leaf in scope.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	authkubernetes "github.com/hashicorp/vault/api/auth/kubernetes"

	"github.com/secrets-bridge/core/providers"
)

// Kind is the canonical provider name used during Registry lookups.
const Kind = "vault"

// Config keys recognised by New.
const (
	ConfigAddress             = "address"
	ConfigNamespace           = "namespace"
	ConfigAuthMethod          = "authMethod"
	ConfigKubernetesRole      = "kubernetesRole"
	ConfigKubernetesMountPath = "kubernetesMountPath"
	ConfigKubernetesTokenPath = "kubernetesTokenPath"
	ConfigToken               = "token"
	ConfigKVMount             = "kvMount"
	ConfigKVPrefix            = "kvPrefix"
)

const (
	defaultKVMount     = "kv"
	authMethodK8s      = "kubernetes"
	authMethodToken    = "token"
	tokenRefreshMargin = 30 * time.Second
)

// Register wires the Vault factory into r under Kind. Call from main
// during startup; the package does NOT register itself via init() to
// keep global state out of test binaries.
func Register(r *providers.Registry) {
	r.Register(Kind, New)
}

// vaultLogical is the small slice of the Vault API client that Provider
// actually calls. Defining it as an interface lets unit tests inject a
// fake; the real *vaultapi.Logical satisfies the same shape.
type vaultLogical interface {
	ReadWithContext(ctx context.Context, p string) (*vaultapi.Secret, error)
	WriteWithContext(ctx context.Context, p string, data map[string]any) (*vaultapi.Secret, error)
	ListWithContext(ctx context.Context, p string) (*vaultapi.Secret, error)
}

// Provider is a HashiCorp Vault KV v2 backend speaking the new
// metadata/value-split providers.Provider interface.
type Provider struct {
	logical  vaultLogical
	kvMount  string
	kvPrefix string

	authFn      func(ctx context.Context) error
	tokenMu     sync.Mutex
	tokenExpiry time.Time
}

// New constructs a Provider from a Config block.
func New(ctx context.Context, cfg providers.Config) (providers.Provider, error) {
	addr, _ := cfg[ConfigAddress].(string)
	if addr == "" {
		return nil, fmt.Errorf("vault: %s is required", ConfigAddress)
	}

	vc, err := vaultapi.NewClient(&vaultapi.Config{Address: addr})
	if err != nil {
		return nil, fmt.Errorf("vault: build client: %w", err)
	}
	if ns, _ := cfg[ConfigNamespace].(string); ns != "" {
		vc.SetNamespace(ns)
	}

	kvMount := defaultKVMount
	if m, _ := cfg[ConfigKVMount].(string); m != "" {
		kvMount = strings.Trim(m, "/")
	}
	kvPrefix := strings.Trim(stringFromCfg(cfg, ConfigKVPrefix), "/")

	p := &Provider{
		logical:  vc.Logical(),
		kvMount:  kvMount,
		kvPrefix: kvPrefix,
	}

	method := stringFromCfg(cfg, ConfigAuthMethod)
	if method == "" {
		method = authMethodK8s
	}
	switch method {
	case authMethodToken:
		t := stringFromCfg(cfg, ConfigToken)
		if t == "" {
			return nil, fmt.Errorf("vault: authMethod=%s requires %s", authMethodToken, ConfigToken)
		}
		vc.SetToken(t)
		p.setExpiry(time.Now().Add(100 * 365 * 24 * time.Hour))

	case authMethodK8s:
		role := stringFromCfg(cfg, ConfigKubernetesRole)
		if role == "" {
			return nil, fmt.Errorf("vault: authMethod=%s requires %s", authMethodK8s, ConfigKubernetesRole)
		}
		opts := []authkubernetes.LoginOption{}
		if m := stringFromCfg(cfg, ConfigKubernetesMountPath); m != "" {
			opts = append(opts, authkubernetes.WithMountPath(m))
		}
		if t := stringFromCfg(cfg, ConfigKubernetesTokenPath); t != "" {
			opts = append(opts, authkubernetes.WithServiceAccountTokenPath(t))
		}
		p.authFn = func(ctx context.Context) error {
			k8sAuth, err := authkubernetes.NewKubernetesAuth(role, opts...)
			if err != nil {
				return fmt.Errorf("vault: build kubernetes auth: %w", err)
			}
			secret, err := vc.Auth().Login(ctx, k8sAuth)
			if err != nil {
				return fmt.Errorf("vault: kubernetes login: %w", err)
			}
			if secret == nil || secret.Auth == nil {
				return errors.New("vault: kubernetes login returned no auth")
			}
			p.setExpiry(time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second))
			return nil
		}
		if err := p.authFn(ctx); err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("vault: unsupported authMethod %q", method)
	}

	return p, nil
}

// GetMetadata reads KV v2 metadata for ref.Name without ever touching
// the value subtree.
func (p *Provider) GetMetadata(ctx context.Context, ref providers.SecretRef) (providers.SecretMetadata, error) {
	if err := p.renew(ctx); err != nil {
		return providers.SecretMetadata{}, err
	}
	metaPath := p.metadataPath(ref.Name)
	resp, err := p.logical.ReadWithContext(ctx, metaPath)
	if err != nil {
		return providers.SecretMetadata{}, fmt.Errorf("vault: read %s: %w", metaPath, err)
	}
	if resp == nil || resp.Data == nil {
		return providers.SecretMetadata{}, fmt.Errorf("%w: %s", providers.ErrNotFound, ref)
	}
	return metadataFromKVv2(ref, resp.Data), nil
}

// ListMetadata walks the KV v2 metadata subtree under scope and
// returns one SecretMetadata per leaf. Scope.Scope may override the
// configured kvPrefix.
func (p *Provider) ListMetadata(ctx context.Context, scope providers.ProviderScope) ([]providers.SecretMetadata, error) {
	if err := p.renew(ctx); err != nil {
		return nil, err
	}
	prefix := p.kvPrefix
	if scope.Scope != "" {
		prefix = strings.Trim(scope.Scope, "/")
	}

	var leaves []string
	if err := p.walk(ctx, prefix, "", &leaves); err != nil {
		return nil, err
	}

	out := make([]providers.SecretMetadata, 0, len(leaves))
	for _, leaf := range leaves {
		ref := providers.SecretRef{
			Provider: Kind,
			Scope:    scope.Scope,
			Name:     leaf,
		}
		// Fetch metadata per-leaf so the returned slice contains
		// version + timestamps, not just names. This is N+1 reads
		// against Vault — acceptable for the volumes we expect; a
		// future optimization can fold list+read into a single
		// scripted call.
		md, err := p.GetMetadata(ctx, ref)
		if err != nil {
			// A delete between list and read race-loses; skip
			// rather than fail the entire enumeration.
			if errors.Is(err, providers.ErrNotFound) {
				continue
			}
			return nil, err
		}
		out = append(out, md)
	}
	return out, nil
}

// GetValue reads the KV v2 data subtree for ref.Name. Callers MUST NOT
// log the returned SecretValue.Bytes.
func (p *Provider) GetValue(ctx context.Context, ref providers.SecretRef) (providers.SecretValue, error) {
	if err := p.renew(ctx); err != nil {
		return providers.SecretValue{}, err
	}
	dataPath := p.dataPath(ref.Name)
	resp, err := p.logical.ReadWithContext(ctx, dataPath)
	if err != nil {
		return providers.SecretValue{}, fmt.Errorf("vault: read %s: %w", dataPath, err)
	}
	if resp == nil || resp.Data == nil {
		return providers.SecretValue{}, fmt.Errorf("%w: %s", providers.ErrNotFound, ref)
	}
	dataRaw, ok := resp.Data["data"].(map[string]any)
	if !ok {
		return providers.SecretValue{}, fmt.Errorf("vault: %s: missing data field", dataPath)
	}
	payload, err := json.Marshal(dataRaw)
	if err != nil {
		return providers.SecretValue{}, fmt.Errorf("vault: marshal %s: %w", dataPath, err)
	}
	return providers.SecretValue{
		Bytes:       payload,
		ContentType: "application/json",
	}, nil
}

// PutValue writes a new KV v2 version. The input bytes are interpreted
// as a JSON object payload (`{"k":"v",...}`); non-JSON input is wrapped
// as `{"value":"<raw>"}` so callers don't have to think about the KV
// v2 envelope.
func (p *Provider) PutValue(ctx context.Context, ref providers.SecretRef, value providers.SecretValue, opts providers.PutOptions) (providers.SecretVersion, error) {
	if err := p.renew(ctx); err != nil {
		return providers.SecretVersion{}, err
	}

	var kv map[string]any
	if err := json.Unmarshal(value.Bytes, &kv); err != nil || kv == nil {
		kv = map[string]any{"value": string(value.Bytes)}
	}

	dataPath := p.dataPath(ref.Name)
	resp, err := p.logical.WriteWithContext(ctx, dataPath, map[string]any{"data": kv})
	if err != nil {
		return providers.SecretVersion{}, fmt.Errorf("vault: write %s: %w", dataPath, err)
	}
	return versionFromWrite(resp), nil
}

// renew re-authenticates if we're inside the refresh margin.
func (p *Provider) renew(ctx context.Context) error {
	if p.authFn == nil {
		return nil // token auth or test injection
	}
	p.tokenMu.Lock()
	near := time.Until(p.tokenExpiry) < tokenRefreshMargin
	p.tokenMu.Unlock()
	if !near {
		return nil
	}
	return p.authFn(ctx)
}

func (p *Provider) setExpiry(t time.Time) {
	p.tokenMu.Lock()
	p.tokenExpiry = t
	p.tokenMu.Unlock()
}

// dataPath joins the mount, "data", optional prefix, and the secret
// name into a KV v2 read/write path.
func (p *Provider) dataPath(name string) string {
	return p.kvJoin("data", name)
}

// metadataPath is the metadata-side companion to dataPath.
func (p *Provider) metadataPath(name string) string {
	return p.kvJoin("metadata", name)
}

func (p *Provider) kvJoin(api, suffix string) string {
	parts := []string{p.kvMount, api}
	if p.kvPrefix != "" {
		parts = append(parts, p.kvPrefix)
	}
	if suffix != "" {
		parts = append(parts, suffix)
	}
	return path.Join(parts...)
}

// walk recursively enumerates leaves under the configured prefix +
// suffix. Suffix is the in-progress relative path during recursion.
func (p *Provider) walk(ctx context.Context, prefix, suffix string, out *[]string) error {
	listPath := path.Join(p.kvMount, "metadata")
	if prefix != "" {
		listPath = path.Join(listPath, prefix)
	}
	if suffix != "" {
		listPath = path.Join(listPath, suffix)
	}

	secret, err := p.logical.ListWithContext(ctx, listPath)
	if err != nil {
		return fmt.Errorf("vault: list %s: %w", listPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil
	}
	keysRaw, ok := secret.Data["keys"].([]any)
	if !ok {
		return nil
	}
	for _, k := range keysRaw {
		ks, ok := k.(string)
		if !ok {
			continue
		}
		child := path.Join(suffix, strings.TrimSuffix(ks, "/"))
		if strings.HasSuffix(ks, "/") {
			if err := p.walk(ctx, prefix, child, out); err != nil {
				return err
			}
			continue
		}
		*out = append(*out, child)
	}
	return nil
}

func metadataFromKVv2(ref providers.SecretRef, data map[string]any) providers.SecretMetadata {
	md := providers.SecretMetadata{Ref: ref}
	if v, ok := data["created_time"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			md.CreatedAt = t
		}
	}
	if v, ok := data["updated_time"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			md.UpdatedAt = t
		}
	}
	if v, ok := data["current_version"]; ok {
		md.Version = providers.SecretVersion{
			ID:        fmt.Sprintf("%v", v),
			CreatedAt: md.UpdatedAt,
		}
	}
	if cm, ok := data["custom_metadata"].(map[string]any); ok && len(cm) > 0 {
		labels := make(map[string]string, len(cm))
		for k, v := range cm {
			labels[k] = fmt.Sprintf("%v", v)
		}
		md.Labels = labels
	}
	return md
}

func versionFromWrite(s *vaultapi.Secret) providers.SecretVersion {
	if s == nil || s.Data == nil {
		return providers.SecretVersion{CreatedAt: time.Now().UTC()}
	}
	out := providers.SecretVersion{CreatedAt: time.Now().UTC()}
	if v, ok := s.Data["version"]; ok {
		out.ID = fmt.Sprintf("%v", v)
	}
	if v, ok := s.Data["created_time"].(string); ok && v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			out.CreatedAt = t
		}
	}
	return out
}

func stringFromCfg(cfg providers.Config, key string) string {
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}
