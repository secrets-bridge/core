package providers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeProvider is a minimal Provider used by tests that only need a
// constructible value — it never returns a real secret.
type fakeProvider struct{ id string }

func (fakeProvider) GetMetadata(context.Context, SecretRef) (SecretMetadata, error) {
	return SecretMetadata{}, ErrNotFound
}
func (fakeProvider) ListMetadata(context.Context, ProviderScope) ([]SecretMetadata, error) {
	return nil, nil
}
func (fakeProvider) GetValue(context.Context, SecretRef) (SecretValue, error) {
	return SecretValue{}, ErrNotFound
}
func (fakeProvider) PutValue(context.Context, SecretRef, SecretValue, PutOptions) (SecretVersion, error) {
	return SecretVersion{}, nil
}

func TestSecretRef_String(t *testing.T) {
	cases := []struct {
		name string
		ref  SecretRef
		want string
	}{
		{
			name: "without version",
			ref:  SecretRef{Provider: "vault", Scope: "kv/data/app", Name: "db"},
			want: "vault://kv/data/app/db",
		},
		{
			name: "with version",
			ref:  SecretRef{Provider: "aws-sm", Scope: "us-east-1", Name: "api/token", Version: "v3"},
			want: "aws-sm://us-east-1/api/token@v3",
		},
		{
			name: "empty scope",
			ref:  SecretRef{Provider: "gcp-sm", Scope: "", Name: "k"},
			want: "gcp-sm:///k",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ref.String(); got != tc.want {
				t.Fatalf("String(): got %q want %q", got, tc.want)
			}
		})
	}
}

// SecretValue must redact itself under every default formatting verb so a
// stray fmt.Sprintf / log statement can't leak the bytes.
func TestSecretValue_Redaction(t *testing.T) {
	v := SecretValue{Bytes: []byte("super-secret-token"), ContentType: "text/plain"}

	cases := map[string]string{
		"String()":     v.String(),
		"GoString()":   v.GoString(),
		"fmt %v":       fmt.Sprintf("%v", v),
		"fmt %s":       fmt.Sprintf("%s", v),
		"fmt %+v":      fmt.Sprintf("%+v", v),
		"fmt %#v":      fmt.Sprintf("%#v", v),
		"fmt in error": fmt.Errorf("oh no: %v", v).Error(),
	}
	for label, got := range cases {
		if strings.Contains(got, "super-secret-token") {
			t.Errorf("%s leaked the secret bytes: %q", label, got)
		}
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("%s did not contain <redacted>: %q", label, got)
		}
	}

	// The bytes themselves remain accessible to code that explicitly
	// reads them — redaction is about *accidental* disclosure, not
	// preventing intentional access.
	if string(v.Bytes) != "super-secret-token" {
		t.Fatalf("Bytes was tampered with by redaction logic")
	}
}

func TestRegistry_RegisterAndBuild(t *testing.T) {
	r := NewRegistry()

	r.Register("fake", func(ctx context.Context, cfg Config) (Provider, error) {
		return fakeProvider{id: fmt.Sprint(cfg["id"])}, nil
	})

	got, err := r.Build(context.Background(), "fake", Config{"id": "one"})
	if err != nil {
		t.Fatalf("Build: unexpected error: %v", err)
	}
	if got.(fakeProvider).id != "one" {
		t.Fatalf("factory did not receive config: got id=%q", got.(fakeProvider).id)
	}
}

// Build must return a wrapped ErrProviderNotRegistered so callers can use
// errors.Is to distinguish "no such kind" from a factory-side failure.
func TestRegistry_Build_Unregistered(t *testing.T) {
	r := NewRegistry()

	_, err := r.Build(context.Background(), "missing", nil)
	if err == nil {
		t.Fatal("Build returned nil error for an unregistered kind")
	}
	if !errors.Is(err, ErrProviderNotRegistered) {
		t.Fatalf("error does not wrap ErrProviderNotRegistered: %v", err)
	}
	if !strings.Contains(err.Error(), `"missing"`) {
		t.Fatalf("error does not name the missing kind: %v", err)
	}
}

// Factory-side errors must propagate as-is — the registry must not wrap
// them in ErrProviderNotRegistered, which would confuse callers using
// errors.Is for that sentinel.
func TestRegistry_Build_FactoryError(t *testing.T) {
	r := NewRegistry()
	want := errors.New("factory boom")
	r.Register("explodes", func(context.Context, Config) (Provider, error) { return nil, want })

	_, err := r.Build(context.Background(), "explodes", nil)
	if !errors.Is(err, want) {
		t.Fatalf("factory error not propagated: %v", err)
	}
	if errors.Is(err, ErrProviderNotRegistered) {
		t.Fatalf("factory error was mis-wrapped as ErrProviderNotRegistered: %v", err)
	}
}

func TestRegistry_RegisterOverwrites(t *testing.T) {
	r := NewRegistry()
	r.Register("k", func(context.Context, Config) (Provider, error) { return fakeProvider{id: "first"}, nil })
	r.Register("k", func(context.Context, Config) (Provider, error) { return fakeProvider{id: "second"}, nil })

	got, err := r.Build(context.Background(), "k", nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got.(fakeProvider).id != "second" {
		t.Fatalf("re-register did not overwrite: got id=%q want %q", got.(fakeProvider).id, "second")
	}
}

func TestRegistry_Kinds(t *testing.T) {
	r := NewRegistry()
	for _, k := range []string{"vault", "aws-sm", "gcp-sm"} {
		r.Register(k, func(context.Context, Config) (Provider, error) { return fakeProvider{}, nil })
	}
	got := r.Kinds()
	sort.Strings(got)
	want := []string{"aws-sm", "gcp-sm", "vault"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Kinds: got %v want %v", got, want)
	}
}

// Run with -race in CI to catch any unsynchronized access to the
// factories map. Mixing reads (Build, Kinds) with writes (Register) is
// the supported usage pattern.
func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()

	const goroutines = 16
	const iters = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			kind := fmt.Sprintf("k-%d", i%4)
			for j := 0; j < iters; j++ {
				switch j % 3 {
				case 0:
					r.Register(kind, func(context.Context, Config) (Provider, error) {
						return fakeProvider{}, nil
					})
				case 1:
					_, _ = r.Build(context.Background(), kind, nil)
				case 2:
					_ = r.Kinds()
				}
			}
		}()
	}
	wg.Wait()
}
