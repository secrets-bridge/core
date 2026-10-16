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
//
// custom_metadata trust boundary:
//   - GetMetadata and ListMetadata copy a KV v2 path's custom_metadata
//     into SecretMetadata.Labels (see that field's doc comment in
//     providers.SecretMetadata for the general contract). custom_metadata
//     is operator-supplied and lives in Vault's metadata plane, which is
//     usually writable by a broader set of principals than the data
//     plane; whatever is present there is copied verbatim and the
//     control plane persists + returns it via GET /secrets.
//   - By default every custom_metadata key is copied, preserving prior
//     behavior. Deployments that cannot guarantee operators keep
//     sensitive material out of custom_metadata should set
//     ConfigLabelAllowlist to the specific keys that are safe to expose
//     in the catalog; every other key is dropped entirely (not just its
//     value).
//   - This connector never reads or copies KV v2 secret DATA into
//     Labels — only the metadata endpoint's custom_metadata block.
//
// Path safety:
//   - Every Vault path is assembled from kvMount, the KV v2 API segment,
//     kvPrefix (or a list scope) and the secret name. Each part is
//     validated and the parts are joined verbatim; nothing is cleaned or
//     resolved, so a name can never climb out of the prefix or the mount.
//   - A part is refused with ErrInvalidPath, before any request is made,
//     if it has a "." or ".." segment, an empty segment, a backslash, a
//     control character, invalid UTF-8, or a percent-encoded ".", "/" or
//     "\" (checked again after each layer of percent-decoding).
//   - kvMount, kvPrefix and list scopes may carry one leading and one
//     trailing "/" ("secret/", "/prod/"); those are stripped. A secret
//     name must already be canonical: no leading or trailing "/".
//   - Keys returned by a LIST that fail the same rules are skipped, not
//     followed.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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
	// ConfigLabelAllowlist is an optional list of custom_metadata keys
	// permitted to propagate into SecretMetadata.Labels. Accepts
	// []string or []any of strings (the latter is what comes out of a
	// JSON/YAML unmarshal). Empty / nil / absent means "no allowlist" —
	// every custom_metadata key is copied, matching the pre-existing
	// default. See the package doc's "custom_metadata trust boundary"
	// note for why a deployment might want to set this.
	ConfigLabelAllowlist = "labelAllowlist"
)

const (
	defaultKVMount     = "kv"
	authMethodK8s      = "kubernetes"
	authMethodToken    = "token"
	tokenRefreshMargin = 30 * time.Second
)

// ErrInvalidPath is returned when a secret name, list scope, kvMount or
// kvPrefix is not a safe KV path (see "Path safety" in the package doc).
// The error says which part failed and why, but never echoes the input
// and never carries a secret value, so it is safe to log and to return
// to the control plane. It is deliberately distinct from
// providers.ErrNotFound: the request was refused, not looked up.
var ErrInvalidPath = errors.New("vault: invalid path")

// Names of the path parts, used in ErrInvalidPath messages.
const (
	partName  = "secret name"
	partScope = "list scope"
	partMount = ConfigKVMount
	partPfx   = ConfigKVPrefix
)

// maxPercentDecodes bounds how many layers of percent-encoding a part
// may carry before it is refused outright.
const maxPercentDecodes = 3

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

	// labelAllowlist restricts which custom_metadata keys are copied
	// into SecretMetadata.Labels. nil means "no allowlist" — every key
	// is copied (see ConfigLabelAllowlist and the package doc's
	// "custom_metadata trust boundary" note).
	labelAllowlist map[string]struct{}

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

	kvMount := defaultKVMount
	if m, _ := cfg[ConfigKVMount].(string); m != "" {
		clean, err := cleanDir(partMount, m)
		if err != nil {
			return nil, err
		}
		if clean == "" {
			return nil, invalidPath(partMount, "has no path segments")
		}
		kvMount = clean
	}
	kvPrefix, err := cleanDir(partPfx, stringFromCfg(cfg, ConfigKVPrefix))
	if err != nil {
		return nil, err
	}

	vc, err := vaultapi.NewClient(&vaultapi.Config{Address: addr})
	if err != nil {
		return nil, fmt.Errorf("vault: build client: %w", err)
	}
	if ns, _ := cfg[ConfigNamespace].(string); ns != "" {
		vc.SetNamespace(ns)
	}

	labelAllowlist, err := readLabelAllowlist(cfg[ConfigLabelAllowlist])
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}

	p := &Provider{
		logical:        vc.Logical(),
		kvMount:        kvMount,
		kvPrefix:       kvPrefix,
		labelAllowlist: labelAllowlist,
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
// the value subtree. The returned SecretMetadata.Labels is populated
// from Vault's custom_metadata — see the package doc's "custom_metadata
// trust boundary" note before relying on Labels for anything beyond
// display/filtering.
func (p *Provider) GetMetadata(ctx context.Context, ref providers.SecretRef) (providers.SecretMetadata, error) {
	metaPath, err := p.metadataPath(ref.Name)
	if err != nil {
		return providers.SecretMetadata{}, err
	}
	if err := p.renew(ctx); err != nil {
		return providers.SecretMetadata{}, err
	}
	resp, err := p.logical.ReadWithContext(ctx, metaPath)
	if err != nil {
		return providers.SecretMetadata{}, fmt.Errorf("vault: read %s: %w", metaPath, err)
	}
	if resp == nil || resp.Data == nil {
		return providers.SecretMetadata{}, fmt.Errorf("%w: %s", providers.ErrNotFound, ref)
	}
	return p.metadataFromKVv2(ref, resp.Data), nil
}

// ListMetadata walks the KV v2 metadata subtree under scope and
// returns one SecretMetadata per leaf. Scope.Scope may override the
// configured kvPrefix.
func (p *Provider) ListMetadata(ctx context.Context, scope providers.ProviderScope) ([]providers.SecretMetadata, error) {
	prefix := p.kvPrefix
	if scope.Scope != "" {
		clean, err := cleanDir(partScope, scope.Scope)
		if err != nil {
			return nil, err
		}
		if clean == "" {
			// "/" would otherwise widen the listing to the whole mount.
			return nil, invalidPath(partScope, "has no path segments")
		}
		prefix = clean
	}
	// Validate the root list path up front so a bad mount or prefix is
	// refused before renew() can make a login request.
	if _, err := p.listPath(prefix, ""); err != nil {
		return nil, err
	}
	if err := p.renew(ctx); err != nil {
		return nil, err
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
	dataPath, err := p.dataPath(ref.Name)
	if err != nil {
		return providers.SecretValue{}, err
	}
	if err := p.renew(ctx); err != nil {
		return providers.SecretValue{}, err
	}
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
	dataPath, err := p.dataPath(ref.Name)
	if err != nil {
		return providers.SecretVersion{}, err
	}
	if err := p.renew(ctx); err != nil {
		return providers.SecretVersion{}, err
	}

	var kv map[string]any
	if err := json.Unmarshal(value.Bytes, &kv); err != nil || kv == nil {
		kv = map[string]any{"value": string(value.Bytes)}
	}

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
func (p *Provider) dataPath(name string) (string, error) {
	return p.secretPath("data", name)
}

// metadataPath is the metadata-side companion to dataPath.
func (p *Provider) metadataPath(name string) (string, error) {
	return p.secretPath("metadata", name)
}

// secretPath builds {mount}/{api}/{prefix}/{name}. Every part is
// validated and the parts are joined as-is: no path.Join, so ".." and
// "//" are refused rather than resolved.
func (p *Provider) secretPath(api, name string) (string, error) {
	if name == "" {
		return "", invalidPath(partName, "is empty")
	}
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return "", invalidPath(partName, `must not start or end with "/"`)
	}
	if problem := pathProblem(name); problem != "" {
		return "", invalidPath(partName, problem)
	}
	parts, err := p.basePath(api, p.kvPrefix)
	if err != nil {
		return "", err
	}
	return strings.Join(append(parts, name), "/"), nil
}

// listPath builds {mount}/metadata/{prefix}/{suffix} for a KV v2 LIST.
// prefix is the configured kvPrefix or a cleaned list scope; suffix is
// the relative directory walk has reached.
func (p *Provider) listPath(prefix, suffix string) (string, error) {
	parts, err := p.basePath("metadata", prefix)
	if err != nil {
		return "", err
	}
	if suffix != "" {
		if problem := pathProblem(suffix); problem != "" {
			return "", invalidPath(partName, problem)
		}
		parts = append(parts, suffix)
	}
	return strings.Join(parts, "/"), nil
}

// basePath re-checks the stored mount and prefix on every call, so a
// Provider assembled without New cannot skip validation.
func (p *Provider) basePath(api, prefix string) ([]string, error) {
	if p.kvMount == "" {
		return nil, invalidPath(partMount, "is empty")
	}
	if problem := pathProblem(p.kvMount); problem != "" {
		return nil, invalidPath(partMount, problem)
	}
	parts := []string{p.kvMount, api}
	if prefix != "" {
		if problem := pathProblem(prefix); problem != "" {
			return nil, invalidPath(partPfx, problem)
		}
		parts = append(parts, prefix)
	}
	return parts, nil
}

// cleanDir validates a mount, prefix or list scope. One leading and one
// trailing "/" are accepted and stripped, since "secret/" and "/prod/"
// are common ways to write them; the rest must pass pathProblem. An
// input of "" or "/" returns "" and the caller decides what that means.
func cleanDir(part, s string) (string, error) {
	s = strings.TrimPrefix(s, "/")
	s = strings.TrimSuffix(s, "/")
	if s == "" {
		return "", nil
	}
	if problem := pathProblem(s); problem != "" {
		return "", invalidPath(part, problem)
	}
	return s, nil
}

// pathProblem reports why s is not a safe relative KV path, or "" when it
// is. s is checked as given and again after each layer of
// percent-decoding, so "%252e%252e" is caught as surely as "..", for the
// benefit of any proxy or server that decodes more than once.
func pathProblem(s string) string {
	for decodes := 0; ; decodes++ {
		if problem := layerProblem(s); problem != "" {
			return problem
		}
		next := percentDecode(s)
		if next == s {
			return ""
		}
		if decodes == maxPercentDecodes {
			return "is percent-encoded too many times"
		}
		s = next
	}
}

// layerProblem checks one decoding layer of a path.
func layerProblem(s string) string {
	if !utf8.ValidString(s) {
		return "is not valid UTF-8"
	}
	for _, r := range s {
		if r == '\\' {
			return "contains a backslash"
		}
		if unicode.IsControl(r) {
			return "contains a control character"
		}
	}
	lower := strings.ToLower(s)
	for _, enc := range []string{"%2e", "%2f", "%5c"} {
		if strings.Contains(lower, enc) {
			return `contains a percent-encoded ".", "/" or "\"`
		}
	}
	for _, seg := range strings.Split(s, "/") {
		switch seg {
		case "":
			return "has an empty path segment"
		case ".", "..":
			return `has a "." or ".." path segment`
		}
	}
	return ""
}

// percentDecode decodes every well-formed %XX escape in s and leaves
// anything else (a bare "%", "%zz") as it is. Unlike url.PathUnescape it
// never fails, so a stray "%" cannot hide an encoded "." elsewhere.
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// invalidPath wraps ErrInvalidPath with the part and the rule it broke.
// It never includes the offending input.
func invalidPath(part, problem string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidPath, part, problem)
}

// walk recursively enumerates leaves under the configured prefix +
// suffix. Suffix is the in-progress relative path during recursion.
func (p *Provider) walk(ctx context.Context, prefix, suffix string, out *[]string) error {
	listPath, err := p.listPath(prefix, suffix)
	if err != nil {
		return err
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
		// KV v2 LIST returns one path segment per key, with a trailing
		// "/" for a directory. Anything else ("..", "a/b", an encoded
		// separator) is skipped rather than followed: following it is
		// how a key could steer the walk outside the prefix.
		seg := strings.TrimSuffix(ks, "/")
		if strings.Contains(seg, "/") || pathProblem(seg) != "" {
			continue
		}
		child := seg
		if suffix != "" {
			child = suffix + "/" + seg
		}
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

// metadataFromKVv2 maps a Vault KV v2 metadata response onto
// SecretMetadata. custom_metadata is copied into Labels subject to
// p.labelAllowlist — see the package doc's "custom_metadata trust
// boundary" note and the ConfigLabelAllowlist doc comment. A nil
// labelAllowlist copies every key (the pre-existing default behavior);
// a non-nil one drops any key not explicitly listed, not just its value.
func (p *Provider) metadataFromKVv2(ref providers.SecretRef, data map[string]any) providers.SecretMetadata {
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
			if p.labelAllowlist != nil {
				if _, allowed := p.labelAllowlist[k]; !allowed {
					continue
				}
			}
			labels[k] = fmt.Sprintf("%v", v)
		}
		if len(labels) > 0 {
			md.Labels = labels
		}
	}
	return md
}

// readLabelAllowlist accepts []string or []any (the latter is what
// comes out of a JSON/YAML unmarshal) and returns the set of
// custom_metadata keys allowed to propagate into SecretMetadata.Labels.
// Empty / nil / absent means "no allowlist" — every custom_metadata key
// is copied, preserving the pre-existing default behavior. Non-string
// elements fail loudly so a typo in chart values doesn't silently widen
// the allowlist into a no-op.
func readLabelAllowlist(raw any) (map[string]struct{}, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case []string:
		if len(v) == 0 {
			return nil, nil
		}
		out := make(map[string]struct{}, len(v))
		for _, k := range v {
			out[k] = struct{}{}
		}
		return out, nil
	case []any:
		if len(v) == 0 {
			return nil, nil
		}
		out := make(map[string]struct{}, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("config.labelAllowlist must be a list of strings, got element of type %T", e)
			}
			out[s] = struct{}{}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("config.labelAllowlist must be []string, got %T", raw)
	}
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
