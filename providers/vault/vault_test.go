package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/secrets-bridge/core/providers"
)

// fakeLogical implements vaultLogical so unit tests run without a real
// Vault server. Each method records its inputs and returns the pre-set
// response/error.
type fakeLogical struct {
	readResp map[string]*vaultapi.Secret
	readErr  map[string]error
	listResp map[string]*vaultapi.Secret
	listErr  map[string]error
	writeOK  *vaultapi.Secret
	writeErr error

	lastWritePath string
	lastWriteData map[string]any
}

func (f *fakeLogical) ReadWithContext(_ context.Context, p string) (*vaultapi.Secret, error) {
	if err, ok := f.readErr[p]; ok {
		return nil, err
	}
	return f.readResp[p], nil
}
func (f *fakeLogical) ListWithContext(_ context.Context, p string) (*vaultapi.Secret, error) {
	if err, ok := f.listErr[p]; ok {
		return nil, err
	}
	return f.listResp[p], nil
}
func (f *fakeLogical) WriteWithContext(_ context.Context, p string, data map[string]any) (*vaultapi.Secret, error) {
	f.lastWritePath = p
	f.lastWriteData = data
	return f.writeOK, f.writeErr
}

func newTestProvider(fl *fakeLogical, prefix string) *Provider {
	p := &Provider{
		logical:  fl,
		kvMount:  "kv",
		kvPrefix: prefix,
	}
	p.setExpiry(time.Now().Add(time.Hour))
	return p
}

func TestRegister(t *testing.T) {
	r := providers.NewRegistry()
	Register(r)
	kinds := r.Kinds()
	if len(kinds) != 1 || kinds[0] != Kind {
		t.Fatalf("Register: expected one kind %q, got %v", Kind, kinds)
	}
}

func TestPathBuilding(t *testing.T) {
	cases := []struct {
		name      string
		prefix    string
		secret    string
		wantData  string
		wantMeta  string
	}{
		{"no prefix", "", "apps/db", "kv/data/apps/db", "kv/metadata/apps/db"},
		{"with prefix", "prod-eu", "apps/db", "kv/data/prod-eu/apps/db", "kv/metadata/prod-eu/apps/db"},
		{"prefix with slashes (stored trimmed)", "team-a", "k", "kv/data/team-a/k", "kv/metadata/team-a/k"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(&fakeLogical{}, tc.prefix)
			if got := p.dataPath(tc.secret); got != tc.wantData {
				t.Errorf("dataPath: got %q want %q", got, tc.wantData)
			}
			if got := p.metadataPath(tc.secret); got != tc.wantMeta {
				t.Errorf("metadataPath: got %q want %q", got, tc.wantMeta)
			}
		})
	}
}

func TestGetMetadata_Found(t *testing.T) {
	now := "2026-05-28T01:02:03.456Z"
	fl := &fakeLogical{
		readResp: map[string]*vaultapi.Secret{
			"kv/metadata/apps/db": {
				Data: map[string]any{
					"created_time":    now,
					"updated_time":    now,
					"current_version": 7,
					"custom_metadata": map[string]any{"env": "prod"},
				},
			},
		},
	}
	p := newTestProvider(fl, "")
	ref := providers.SecretRef{Provider: Kind, Name: "apps/db"}

	md, err := p.GetMetadata(t.Context(), ref)
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if md.Version.ID != "7" {
		t.Fatalf("Version.ID: %q", md.Version.ID)
	}
	if md.Labels["env"] != "prod" {
		t.Fatalf("Labels: %v", md.Labels)
	}
	if md.CreatedAt.IsZero() {
		t.Fatal("CreatedAt not parsed from KV v2 metadata")
	}
	if md.Checksum != "" {
		t.Fatal("Checksum must stay empty when populated from KV v2 metadata — " +
			"the metadata endpoint does not expose a content hash and the agent " +
			"is the one that fills this after GetValue.")
	}
}

func TestGetMetadata_NotFound(t *testing.T) {
	// Vault returns nil Secret on missing path; the provider must map
	// that to ErrNotFound so callers can branch on errors.Is.
	fl := &fakeLogical{readResp: map[string]*vaultapi.Secret{}}
	p := newTestProvider(fl, "")

	_, err := p.GetMetadata(t.Context(), providers.SecretRef{Provider: Kind, Name: "missing"})
	if !errors.Is(err, providers.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetValue_ReturnsJSONPayload(t *testing.T) {
	fl := &fakeLogical{
		readResp: map[string]*vaultapi.Secret{
			"kv/data/apps/db": {
				Data: map[string]any{
					"data": map[string]any{
						"password": "p4ss",
						"host":     "db.example",
					},
				},
			},
		},
	}
	p := newTestProvider(fl, "")
	val, err := p.GetValue(t.Context(), providers.SecretRef{Provider: Kind, Name: "apps/db"})
	if err != nil {
		t.Fatalf("GetValue: %v", err)
	}
	if val.ContentType != "application/json" {
		t.Fatalf("ContentType: %q", val.ContentType)
	}
	// Don't pin the exact string (map iteration order) — confirm both
	// fields appear in the marshalled output.
	got := string(val.Bytes)
	if !contains(got, `"password":"p4ss"`) || !contains(got, `"host":"db.example"`) {
		t.Fatalf("payload missing expected keys: %s", got)
	}
}

func TestPutValue_WrapsNonJSONInValueEnvelope(t *testing.T) {
	fl := &fakeLogical{writeOK: &vaultapi.Secret{Data: map[string]any{"version": 3}}}
	p := newTestProvider(fl, "")

	ver, err := p.PutValue(t.Context(),
		providers.SecretRef{Provider: Kind, Name: "x"},
		providers.SecretValue{Bytes: []byte("not-json-just-a-token")},
		providers.PutOptions{},
	)
	if err != nil {
		t.Fatalf("PutValue: %v", err)
	}
	if ver.ID != "3" {
		t.Fatalf("Version.ID: %q", ver.ID)
	}
	// The KV v2 envelope is {"data": {<keys>}}; non-JSON input gets
	// wrapped as {"value": <raw>} so the operator side never has to
	// think about the envelope shape.
	data := fl.lastWriteData["data"].(map[string]any)
	if data["value"] != "not-json-just-a-token" {
		t.Fatalf("non-JSON wrapping wrong: %+v", data)
	}
}

func TestPutValue_PassesJSONObjectThrough(t *testing.T) {
	fl := &fakeLogical{writeOK: &vaultapi.Secret{Data: map[string]any{"version": 4}}}
	p := newTestProvider(fl, "")

	_, err := p.PutValue(t.Context(),
		providers.SecretRef{Provider: Kind, Name: "y"},
		providers.SecretValue{Bytes: []byte(`{"a":"1","b":"2"}`)},
		providers.PutOptions{},
	)
	if err != nil {
		t.Fatalf("PutValue: %v", err)
	}
	data := fl.lastWriteData["data"].(map[string]any)
	if data["a"] != "1" || data["b"] != "2" {
		t.Fatalf("JSON object not passed through verbatim: %+v", data)
	}
	if _, leaked := data["value"]; leaked {
		t.Fatal("JSON object input must NOT be wrapped in a 'value' envelope")
	}
}

func TestListMetadata_WalksAndFetches(t *testing.T) {
	// Tree:
	//   apps/db
	//   apps/web
	// Stored under prefix "prod-eu" so list paths are kv/metadata/prod-eu/...
	const ct = "2026-05-28T01:00:00Z"
	fl := &fakeLogical{
		listResp: map[string]*vaultapi.Secret{
			"kv/metadata/prod-eu": {Data: map[string]any{
				"keys": []any{"apps/"},
			}},
			"kv/metadata/prod-eu/apps": {Data: map[string]any{
				"keys": []any{"db", "web"},
			}},
		},
		readResp: map[string]*vaultapi.Secret{
			"kv/metadata/prod-eu/apps/db": {Data: map[string]any{
				"created_time":    ct,
				"updated_time":    ct,
				"current_version": 1,
			}},
			"kv/metadata/prod-eu/apps/web": {Data: map[string]any{
				"created_time":    ct,
				"updated_time":    ct,
				"current_version": 1,
			}},
		},
	}
	p := newTestProvider(fl, "prod-eu")

	got, err := p.ListMetadata(t.Context(), providers.ProviderScope{Scope: ""})
	if err != nil {
		t.Fatalf("ListMetadata: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 leaves, got %d: %+v", len(got), got)
	}
	names := map[string]bool{}
	for _, m := range got {
		names[m.Ref.Name] = true
	}
	if !names["apps/db"] || !names["apps/web"] {
		t.Fatalf("leaves: %v", names)
	}
}

// New() must reject configurations missing required fields cleanly so
// CR misconfiguration shows up at startup, not on the first request.
func TestNew_RejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  providers.Config
		want string
	}{
		{"address missing", providers.Config{}, "address is required"},
		{"k8s auth without role", providers.Config{
			ConfigAddress:    "https://vault.example.com",
			ConfigAuthMethod: authMethodK8s,
		}, "kubernetesRole"},
		{"token auth without token", providers.Config{
			ConfigAddress:    "https://vault.example.com",
			ConfigAuthMethod: authMethodToken,
		}, "token"},
		{"unsupported auth method", providers.Config{
			ConfigAddress:    "https://vault.example.com",
			ConfigAuthMethod: "approle",
		}, "unsupported authMethod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(t.Context(), tc.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

// indexOf is a tiny strings.Index without pulling the import — keeps the
// test file dependency-light.
func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
