package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/secrets-bridge/core/providers"
)

// CORE-N-01: secret names, list scopes, kvMount and kvPrefix used to be
// glued together with path.Join, which resolves "..". With prefix
// "team-a", the ref "x/../../../other-kv/data/team-b/app/db" became
// /v1/other-kv/data/team-b/app/db, and one more ".." left the KV mount
// for any Vault API path. These tests drive the real vaultapi client
// against an httptest server so they see the exact request that would
// hit Vault.

// unsafePaths are inputs that no secret name, list scope, kvMount or
// kvPrefix may carry, whatever operation uses them.
var unsafePaths = []struct{ name, in string }{
	{"parent segment", ".."},
	{"current segment", "."},
	{"leading parent", "../team-b/app/db"},
	{"audit repro: escape prefix into another mount", "x/../../../other-kv/data/team-b/app/db"},
	{"escape the KV mount entirely", "x/../../../../sys/mounts"},
	{"reach a non-KV endpoint", "../../auth/token/create"},
	{"inner current segment", "apps/./db"},
	{"trailing parent", "apps/db/.."},
	{"empty segment", "apps//db"},
	{"backslash", `apps\db`},
	{"backslash traversal", `apps\..\..\sys`},
	{"NUL", "apps/db\x00"},
	{"newline", "apps/\ndb"},
	{"tab", "apps/\tdb"},
	{"DEL", "apps/db\x7f"},
	{"C1 control", "apps/db\u0085"},
	{"invalid UTF-8 overlong dot", "\xc0\xae\xc0\xae/sys"},
	{"encoded dots", "%2e%2e/team-b/app/db"},
	{"encoded dots upper", "%2E%2E/team-b/app/db"},
	{"encoded dots mixed case", "apps/%2e%2E"},
	{"encoded single dot", "apps/%2e/db"},
	{"encoded slash", "apps%2fdb"},
	{"encoded slash upper", "apps%2Fdb"},
	{"encoded backslash", "apps%5cdb"},
	{"encoded backslash traversal upper", "apps%5C..%5Csys"},
	{"double-encoded dots", "%252e%252e/sys"},
	{"double-encoded slash", "apps%252fdb"},
	{"encoded overlong dot", "%c0%ae%c0%ae/sys"},
	{"encoded NUL", "apps/db%00"},
	{"encoded newline", "apps%0adb"},
	{"nested encoding past the decode limit", "a%252525252520b"},
}

// unsafeNamesOnly are rejected for a secret name but are fine for a
// mount, prefix or scope. A secret name has to be canonical: path.Join
// used to strip a leading or trailing "/" silently, so "/billing/db"
// reached the same secret as "billing/db" while slipping past a plain
// string prefix match on "billing/" in the control plane.
var unsafeNamesOnly = []struct{ name, in string }{
	{"empty", ""},
	{"root", "/"},
	{"leading slash", "/apps/db"},
	{"trailing slash", "apps/db/"},
}

// unreachableVault starts a Vault stand-in that fails the test on any
// request. Validation has to reject bad input before the real client
// puts anything on the wire.
func unreachableVault(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("vault was contacted for rejected input: %s %s", r.Method, r.URL.EscapedPath())
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newHTTPProvider builds a Provider through New (token auth, which makes
// no request) pointed at addr, so the real vaultapi client is in play.
func newHTTPProvider(t *testing.T, addr, mount, prefix string) providers.Provider {
	t.Helper()
	cfg := providers.Config{
		ConfigAddress:    addr,
		ConfigAuthMethod: authMethodToken,
		ConfigToken:      "test-token",
	}
	if mount != "" {
		cfg[ConfigKVMount] = mount
	}
	if prefix != "" {
		cfg[ConfigKVPrefix] = prefix
	}
	p, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

const putPayload = "hunter2-not-a-real-value"

// assertRejected checks that err is a validation failure: not nil, not
// ErrNotFound, and free of the value being written.
func assertRejected(t *testing.T, op string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected a validation error, got nil", op)
	}
	if errors.Is(err, providers.ErrNotFound) {
		t.Fatalf("%s: got ErrNotFound, want a validation error: %v", op, err)
	}
	if !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("%s: error does not say the path is invalid: %v", op, err)
	}
	if strings.Contains(err.Error(), putPayload) {
		t.Fatalf("%s: error leaked the value", op)
	}
}

func TestUnsafeSecretNamesRejectedBeforeAnyRequest(t *testing.T) {
	cases := append(append([]struct{ name, in string }{}, unsafePaths...), unsafeNamesOnly...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newHTTPProvider(t, unreachableVault(t), "kv", "team-a")
			ref := providers.SecretRef{Provider: Kind, Name: tc.in}

			_, err := p.GetMetadata(t.Context(), ref)
			assertRejected(t, "GetMetadata", err)

			_, err = p.GetValue(t.Context(), ref)
			assertRejected(t, "GetValue", err)

			_, err = p.PutValue(t.Context(), ref,
				providers.SecretValue{Bytes: []byte(putPayload)}, providers.PutOptions{})
			assertRejected(t, "PutValue", err)
		})
	}
}

func TestUnsafeListScopeRejectedBeforeAnyRequest(t *testing.T) {
	cases := append(append([]struct{ name, in string }{}, unsafePaths...),
		struct{ name, in string }{"root only", "/"},
		struct{ name, in string }{"double slash only", "//"},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newHTTPProvider(t, unreachableVault(t), "kv", "team-a")
			_, err := p.ListMetadata(t.Context(), providers.ProviderScope{Provider: Kind, Scope: tc.in})
			assertRejected(t, "ListMetadata", err)
		})
	}
}

func TestNewRejectsUnsafeMountAndPrefix(t *testing.T) {
	for _, tc := range unsafePaths {
		t.Run(tc.name, func(t *testing.T) {
			addr := unreachableVault(t)
			for _, key := range []string{ConfigKVMount, ConfigKVPrefix} {
				_, err := New(t.Context(), providers.Config{
					ConfigAddress:    addr,
					ConfigAuthMethod: authMethodToken,
					ConfigToken:      "test-token",
					key:              tc.in,
				})
				assertRejected(t, "New "+key, err)
				if !strings.Contains(err.Error(), key) {
					t.Fatalf("New %s: error does not name the field: %v", key, err)
				}
			}
		})
	}
	t.Run("mount with no segments", func(t *testing.T) {
		_, err := New(t.Context(), providers.Config{
			ConfigAddress:    unreachableVault(t),
			ConfigAuthMethod: authMethodToken,
			ConfigToken:      "test-token",
			ConfigKVMount:    "/",
		})
		assertRejected(t, "New kvMount=/", err)
	})
}

// countingLogical fails closed: it records every call so a test can
// prove nothing reached the Vault client.
type countingLogical struct {
	mu    sync.Mutex
	calls []string
}

func (c *countingLogical) record(op, p string) {
	c.mu.Lock()
	c.calls = append(c.calls, op+" "+p)
	c.mu.Unlock()
}
func (c *countingLogical) ReadWithContext(_ context.Context, p string) (*vaultapi.Secret, error) {
	c.record("read", p)
	return nil, nil
}
func (c *countingLogical) ListWithContext(_ context.Context, p string) (*vaultapi.Secret, error) {
	c.record("list", p)
	return nil, nil
}
func (c *countingLogical) WriteWithContext(_ context.Context, p string, _ map[string]any) (*vaultapi.Secret, error) {
	c.record("write", p)
	return nil, nil
}

// A Provider assembled without New (tests, a future constructor) must
// still refuse an unsafe stored mount or prefix at call time.
func TestUnsafeStoredMountOrPrefixRejectedAtCallTime(t *testing.T) {
	cases := []struct{ name, mount, prefix string }{
		{"prefix walks up", "kv", "team-a/../team-b"},
		{"prefix is parent", "kv", ".."},
		{"mount walks up", "kv/../sys", ""},
		{"mount empty", "", ""},
		{"prefix encoded dots", "kv", "%2e%2e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fl := &countingLogical{}
			p := &Provider{logical: fl, kvMount: tc.mount, kvPrefix: tc.prefix}
			p.setExpiry(time.Now().Add(time.Hour))
			ref := providers.SecretRef{Provider: Kind, Name: "apps/db"}

			_, err := p.GetMetadata(t.Context(), ref)
			assertRejected(t, "GetMetadata", err)
			_, err = p.GetValue(t.Context(), ref)
			assertRejected(t, "GetValue", err)
			_, err = p.PutValue(t.Context(), ref, providers.SecretValue{Bytes: []byte(putPayload)}, providers.PutOptions{})
			assertRejected(t, "PutValue", err)
			_, err = p.ListMetadata(t.Context(), providers.ProviderScope{Provider: Kind})
			assertRejected(t, "ListMetadata", err)

			if len(fl.calls) != 0 {
				t.Fatalf("vault client was called: %v", fl.calls)
			}
		})
	}
}

const maxRecordedRequests = 50

// recordingVault answers like a KV v2 server and records every request
// as "METHOD /escaped/path[?list]".
type recordingVault struct {
	mu   sync.Mutex
	reqs []string
	// listKeys maps a decoded list path to the keys to return for it.
	listKeys map[string][]string
}

func (rv *recordingVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isList := r.URL.Query().Get("list") == "true"
	line := r.Method + " " + r.URL.EscapedPath()
	if isList {
		line += "?list"
	}
	rv.mu.Lock()
	rv.reqs = append(rv.reqs, line)
	n := len(rv.reqs)
	rv.mu.Unlock()

	// A "./" or "/" key used to send walk back into the same directory
	// forever. Cut that off so the test fails instead of hanging.
	if n > maxRecordedRequests {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if isList {
		keys, ok := rv.listKeys[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := json.Marshal(map[string]any{"data": map[string]any{"keys": keys}})
		_, _ = w.Write(body)
		return
	}
	// One body serves every non-list call: metadata reads use
	// current_version, data reads use data, writes use version.
	_, _ = w.Write([]byte(`{"data":{"current_version":1,"version":2,"data":{"k":"v"}}}`))
}

func (rv *recordingVault) requests() []string {
	rv.mu.Lock()
	defer rv.mu.Unlock()
	return append([]string(nil), rv.reqs...)
}

func startRecordingVault(t *testing.T, listKeys map[string][]string) (*recordingVault, string) {
	t.Helper()
	rv := &recordingVault{listKeys: listKeys}
	srv := httptest.NewServer(rv)
	t.Cleanup(srv.Close)
	return rv, srv.URL
}

// Legit mounts, prefixes and names must keep resolving to exactly the
// paths they did before validation was added.
func TestLegitPathsResolveAsBefore(t *testing.T) {
	cases := []struct {
		name, mount, prefix, secret string
		wantMeta, wantData          string
	}{
		{"default mount, no prefix", "", "", "apps/db",
			"/v1/kv/metadata/apps/db", "/v1/kv/data/apps/db"},
		{"chart README form: trailing slashes", "secret/", "prod/", "apps/db",
			"/v1/secret/metadata/prod/apps/db", "/v1/secret/data/prod/apps/db"},
		{"leading and trailing slashes on mount and prefix", "/kv/", "/team-a/", "app/db",
			"/v1/kv/metadata/team-a/app/db", "/v1/kv/data/team-a/app/db"},
		{"multi-segment prefix", "kv", "team-alpha/uat", "db",
			"/v1/kv/metadata/team-alpha/uat/db", "/v1/kv/data/team-alpha/uat/db"},
		{"dots inside segments", "kv", "team-a", "web/db.v2/a..b",
			"/v1/kv/metadata/team-a/web/db.v2/a..b", "/v1/kv/data/team-a/web/db.v2/a..b"},
		{"dotfile name", "kv", "", "apps/.env",
			"/v1/kv/metadata/apps/.env", "/v1/kv/data/apps/.env"},
		{"space and plain percent", "kv", "", "team alpha/promo-50%",
			"/v1/kv/metadata/team%20alpha/promo-50%25", "/v1/kv/data/team%20alpha/promo-50%25"},
		{"percent-encoded non-separator", "kv", "", "a%20b",
			"/v1/kv/metadata/a%2520b", "/v1/kv/data/a%2520b"},
		{"unicode", "kv", "", "café/db",
			"/v1/kv/metadata/caf%C3%A9/db", "/v1/kv/data/caf%C3%A9/db"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, addr := startRecordingVault(t, nil)
			p := newHTTPProvider(t, addr, tc.mount, tc.prefix)
			ref := providers.SecretRef{Provider: Kind, Name: tc.secret}

			if _, err := p.GetMetadata(t.Context(), ref); err != nil {
				t.Fatalf("GetMetadata: %v", err)
			}
			if _, err := p.GetValue(t.Context(), ref); err != nil {
				t.Fatalf("GetValue: %v", err)
			}
			if _, err := p.PutValue(t.Context(), ref,
				providers.SecretValue{Bytes: []byte(`{"k":"v"}`)}, providers.PutOptions{}); err != nil {
				t.Fatalf("PutValue: %v", err)
			}
			want := []string{
				"GET " + tc.wantMeta,
				"GET " + tc.wantData,
				"PUT " + tc.wantData,
			}
			got := rv.requests()
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("requests:\n got  %q\n want %q", got, want)
			}
		})
	}
}

func TestLegitListScopesResolveAsBefore(t *testing.T) {
	cases := []struct {
		name, prefix, scope string
		listBase            string // decoded list path for the scope root
		metaBase            string // decoded metadata path prefix for each leaf
	}{
		{"configured prefix", "team-a", "", "/v1/kv/metadata/team-a", "/v1/kv/metadata/team-a"},
		{"configured prefix with slashes", "/team-a/", "", "/v1/kv/metadata/team-a", "/v1/kv/metadata/team-a"},
		{"no prefix lists the mount", "", "", "/v1/kv/metadata", "/v1/kv/metadata"},
		{"explicit scope with slashes", "team-a/uat", "/team-a/uat/", "/v1/kv/metadata/team-a/uat", "/v1/kv/metadata/team-a/uat"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rv, addr := startRecordingVault(t, map[string][]string{
				tc.listBase:          {"db", "sub/"},
				tc.listBase + "/sub": {"leaf"},
			})
			p := newHTTPProvider(t, addr, "kv", tc.prefix)
			got, err := p.ListMetadata(t.Context(), providers.ProviderScope{Provider: Kind, Scope: tc.scope})
			if err != nil {
				t.Fatalf("ListMetadata: %v", err)
			}
			if len(got) != 2 || got[0].Ref.Name != "db" || got[1].Ref.Name != "sub/leaf" {
				t.Fatalf("leaves: %+v", got)
			}
			want := []string{
				"GET " + tc.listBase + "?list",
				"GET " + tc.listBase + "/sub?list",
				"GET " + tc.metaBase + "/db",
				"GET " + tc.metaBase + "/sub/leaf",
			}
			if reqs := rv.requests(); strings.Join(reqs, "\n") != strings.Join(want, "\n") {
				t.Fatalf("requests:\n got  %q\n want %q", reqs, want)
			}
		})
	}
}

// Keys come back from Vault's LIST, so they are less attacker-reachable
// than refs, but walk used to path.Join them too: a "../" key made it
// list the parent of the prefix. Unsafe keys are now skipped, never
// followed, and the rest of the tree is still enumerated.
func TestListSkipsUnsafeKeysFromVault(t *testing.T) {
	rv, addr := startRecordingVault(t, map[string][]string{
		"/v1/kv/metadata/team-a": {
			"../", "..", ".", "./", "%2e%2e/", "%2E%2E", `bad\name`, "a/b", "", "/", "nul\x00", "ok", "dir/",
		},
		"/v1/kv/metadata/team-a/dir": {"leaf", "../", "%2fescape"},
		// Reachable only if a traversal key is followed.
		"/v1/kv/metadata": {"team-b/"},
	})
	p := newHTTPProvider(t, addr, "kv", "team-a")
	got, err := p.ListMetadata(t.Context(), providers.ProviderScope{Provider: Kind})
	if err != nil {
		t.Fatalf("ListMetadata: %v", err)
	}
	names := make([]string, 0, len(got))
	for _, m := range got {
		names = append(names, m.Ref.Name)
	}
	if strings.Join(names, ",") != "ok,dir/leaf" {
		t.Fatalf("leaves = %q, want [ok dir/leaf]", names)
	}
	want := []string{
		"GET /v1/kv/metadata/team-a?list",
		"GET /v1/kv/metadata/team-a/dir?list",
		"GET /v1/kv/metadata/team-a/ok",
		"GET /v1/kv/metadata/team-a/dir/leaf",
	}
	if reqs := rv.requests(); strings.Join(reqs, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n got  %q\n want %q", reqs, want)
	}
}
