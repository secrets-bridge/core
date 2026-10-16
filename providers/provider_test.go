package providers

import (
	"bytes"
	"context"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
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
		"String()":   v.String(),
		"GoString()": v.GoString(),
		"fmt %v":     fmt.Sprintf("%v", v),
		"fmt %s":     fmt.Sprintf("%s", v), //nolint:staticcheck // S1025: intentional — the test verifies %s reaches String(), not the shortcut

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

// CORE-N-02: String and GoString only covered some verbs. %d, %o, %b,
// %c, %U and friends printed the raw bytes, json.Marshal emitted them as
// base64, and slog's JSONHandler went through json.Marshal. The tests
// below cover every path a value can take into a string by accident.

const redactionSecret = "super-secret-token"

// leakMarkers are fragments of redactionSecret in every encoding a
// formatter, marshaller or log handler emits for a string or []byte.
var leakMarkers = []string{
	"super-secret",    // raw: %s, %q, %c, xml chardata, gob
	"73757065722d",    // %x of "super-"
	"73757065722D",    // %X of "super-"
	"73 75 70 65",     // % x
	"c3VwZXIt",        // base64 of "super-" (encoding/json []byte)
	"115 117 112",     // %v / %d of []byte
	"0x73, 0x75",      // %#v of []byte
	"163 165 160",     // %o of []byte
	"1110011 1110101", // %b of []byte
	"U+0073",          // %U of []byte
	"=115)",           // bad-verb fallback, e.g. %!t(uint8=115)
}

func assertNoLeak(t *testing.T, label, got string) {
	t.Helper()
	for _, m := range leakMarkers {
		if strings.Contains(got, m) {
			t.Errorf("%s leaked the secret (matched %q): %q", label, m, got)
			return
		}
	}
}

func secretFixture() SecretValue {
	return SecretValue{Bytes: []byte(redactionSecret), ContentType: "text/plain"}
}

// Containers a SecretValue can sit in when a caller logs or marshals a
// bigger struct.
type (
	namedField struct {
		Name string
		Val  SecretValue
	}
	pointerField struct {
		Val *SecretValue
	}
	embeddedValue struct {
		SecretValue
		Note string
	}
)

func TestSecretValue_EveryVerbRedacts(t *testing.T) {
	v := secretFixture()
	verbs := []string{
		"%v", "%+v", "%#v", "%s", "%q", "%+q", "%#q", "%x", "%X", "% x", "%#x",
		"%d", "%o", "%O", "%b", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t",
		"%10v", "%-12s", "%.3s", "%08x",
	}
	// Not listed: %p, and %w outside fmt.Errorf or on a non-error. fmt
	// routes those through its bad-verb path, which prints the struct by
	// reflection and never calls Format. go vet rejects both; see the
	// SecretValue doc comment.
	for _, verb := range verbs {
		for label, arg := range map[string]any{"value": v, "pointer": &v} {
			got := fmt.Sprintf(verb, arg)
			assertNoLeak(t, label+" "+verb, got)
			if got != "<redacted>" {
				t.Errorf("%s %s: got %q, want exactly <redacted>", label, verb, got)
			}
		}
	}

	if got := fmt.Sprintf("%T", v); got != "providers.SecretValue" {
		t.Errorf("%%T: got %q", got)
	}
	// Formats held in variables so vet lets the deliberately wrong calls
	// through: they are exactly what a careless log line looks like.
	noVerb, intVerb := "x", "oh no: %d"
	for label, got := range map[string]string{
		"Sprint":       fmt.Sprint(v),
		"Sprintln":     fmt.Sprintln(v),
		"Sprint ptr":   fmt.Sprint(&v),
		"extra arg":    fmt.Sprintf(noVerb, v), //nolint:staticcheck // SA5009: deliberate, exercises the %!(EXTRA ...) path
		"in error":     fmt.Errorf("oh no: %v", v).Error(),
		"in error %d":  fmt.Errorf(intVerb, v).Error(),
		"multiple arg": fmt.Sprintf("%s %x", v, v),
	} {
		assertNoLeak(t, label, got)
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("%s: no <redacted> marker: %q", label, got)
		}
	}
}

func TestSecretValue_NestedFormattingRedacts(t *testing.T) {
	v := secretFixture()
	containers := map[string]any{
		"named field":       namedField{Name: "db", Val: v},
		"pointer field":     pointerField{Val: &v},
		"embedded":          embeddedValue{SecretValue: v, Note: "n"},
		"pointer to struct": &namedField{Name: "db", Val: v},
		"slice":             []SecretValue{v},
		"slice of pointers": []*SecretValue{&v},
		"map value":         map[string]SecretValue{"k": v},
		"interface slice":   []any{v, &v},
	}
	for label, c := range containers {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%U", "%e", "%t"} {
			got := fmt.Sprintf(verb, c)
			assertNoLeak(t, label+" "+verb, got)
		}
	}
}

func TestSecretValue_JSONRedacts(t *testing.T) {
	v := secretFixture()

	for label, arg := range map[string]any{"value": v, "pointer": &v, "embedded (promoted)": embeddedValue{SecretValue: v}} {
		b, err := json.Marshal(arg)
		if err != nil {
			t.Fatalf("%s: json.Marshal: %v", label, err)
		}
		// encoding/json HTML-escapes < and >, so compare the decoded string.
		var got string
		if err := json.Unmarshal(b, &got); err != nil || got != "<redacted>" {
			t.Errorf("%s: got %s (%v), want the JSON string \"<redacted>\"", label, b, err)
		}
	}
	jm, ok := any(v).(json.Marshaler)
	if !ok {
		t.Fatal("SecretValue does not implement json.Marshaler")
	}
	if b, err := jm.MarshalJSON(); err != nil || string(b) != `"<redacted>"` {
		t.Errorf("MarshalJSON: got %s, %v", b, err)
	}

	containers := map[string]any{
		"named field":       namedField{Name: "db", Val: v},
		"pointer field":     pointerField{Val: &v},
		"pointer to struct": &namedField{Name: "db", Val: v},
		"slice":             []SecretValue{v},
		"map value":         map[string]SecretValue{"k": v},
		"map of any":        map[string]any{"v": v, "p": &v},
	}
	for label, c := range containers {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("%s: json.Marshal: %v", label, err)
		}
		assertNoLeak(t, "json "+label, string(b))
		if !strings.Contains(string(b), `redacted`) {
			t.Errorf("json %s: no redacted marker: %s", label, b)
		}

		b, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			t.Fatalf("%s: json.MarshalIndent: %v", label, err)
		}
		assertNoLeak(t, "json indent "+label, string(b))

		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(c); err != nil {
			t.Fatalf("%s: json.Encoder: %v", label, err)
		}
		assertNoLeak(t, "json encoder "+label, buf.String())
	}
}

func TestSecretValue_TextBinaryAndXMLRedact(t *testing.T) {
	v := secretFixture()

	tm, ok := any(v).(encoding.TextMarshaler)
	if !ok {
		t.Fatal("SecretValue does not implement encoding.TextMarshaler")
	}
	if b, err := tm.MarshalText(); err != nil || string(b) != "<redacted>" {
		t.Errorf("MarshalText: %q, %v", b, err)
	}

	bm, ok := any(v).(encoding.BinaryMarshaler)
	if !ok {
		t.Fatal("SecretValue does not implement encoding.BinaryMarshaler")
	}
	if b, err := bm.MarshalBinary(); err != nil || string(b) != "<redacted>" {
		t.Errorf("MarshalBinary: %q, %v", b, err)
	}

	for label, c := range map[string]any{
		"named field":   namedField{Name: "db", Val: v},
		"pointer field": pointerField{Val: &v},
	} {
		b, err := xml.Marshal(c)
		if err != nil {
			t.Fatalf("xml %s: %v", label, err)
		}
		assertNoLeak(t, "xml "+label, string(b))

		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(c); err != nil {
			t.Fatalf("gob %s: %v", label, err)
		}
		assertNoLeak(t, "gob "+label, buf.String())
	}
}

func TestSecretValue_SlogRedacts(t *testing.T) {
	v := secretFixture()

	lv, ok := any(v).(slog.LogValuer)
	if !ok {
		t.Fatal("SecretValue does not implement slog.LogValuer")
	}
	if got := lv.LogValue().String(); got != "<redacted>" {
		t.Errorf("LogValue: got %q", got)
	}

	handlers := map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	}
	for name, mk := range handlers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(mk(&buf))

			logger.Info("kv", "v", v)
			logger.Info("ptr", slog.Any("p", &v))
			logger.Info("group", slog.Group("g", slog.Any("v", v)))
			logger.With("w", v).Info("with")
			logger.WithGroup("wg").Info("withgroup", "v", v)
			logger.Info("named", "s", namedField{Name: "db", Val: v})
			logger.Info("pointer field", "s", pointerField{Val: &v})
			logger.Info("embedded", "s", embeddedValue{SecretValue: v, Note: "n"})
			logger.Info("slice", "s", []SecretValue{v})
			logger.Info("map", "m", map[string]any{"v": v})
			logger.LogAttrs(t.Context(), slog.LevelError, "attrs", slog.Any("v", v))

			out := buf.String()
			assertNoLeak(t, name+" handler", out)
			if n := strings.Count(out, "redacted"); n < 11 {
				t.Errorf("%s handler: expected a redaction marker on every line, got %d:\n%s", name, n, out)
			}
		})
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
