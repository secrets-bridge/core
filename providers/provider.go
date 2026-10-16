// Package providers defines the abstraction over secret backends used by
// the Secrets Bridge platform.
//
// A Provider is split into a metadata plane and a value plane. Metadata
// describes a secret (identity, version, labels, timestamps) and is safe to
// log, cache and replicate. Values are the sensitive payload and must never
// be logged, embedded in errors, serialized to telemetry, or otherwise
// exposed outside an explicit GetValue / PutValue call.
package providers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// ErrNotFound is returned when a SecretRef does not resolve to an existing
// secret in the backing provider.
var ErrNotFound = errors.New("secret not found")

// ErrProviderNotRegistered is returned by the registry when a Factory has
// not been registered for a given provider kind.
var ErrProviderNotRegistered = errors.New("provider not registered")

// SecretRef uniquely identifies a secret within a provider. Version may be
// empty, in which case the provider resolves to the current version.
type SecretRef struct {
	// Provider is the kind of backend (e.g. "vault", "aws-sm").
	Provider string
	// Scope groups secrets within a provider (e.g. a namespace, mount,
	// project). May be empty when the provider is single-scoped.
	Scope string
	// Name is the logical name of the secret within the scope.
	Name string
	// Version pins a specific version. Empty selects the current version.
	Version string
}

// String returns a human-readable, non-sensitive identifier for the ref.
// It must not be used as a stable key — use the struct fields directly.
func (r SecretRef) String() string {
	if r.Version == "" {
		return fmt.Sprintf("%s://%s/%s", r.Provider, r.Scope, r.Name)
	}
	return fmt.Sprintf("%s://%s/%s@%s", r.Provider, r.Scope, r.Name, r.Version)
}

// SecretMetadata describes a secret without exposing its value. Everything
// in this struct is non-sensitive with respect to the secret's VALUE and is
// safe to log and cache — but see the Labels field doc below for a
// narrower trust-boundary caveat that applies specifically to it.
type SecretMetadata struct {
	Ref     SecretRef
	Version SecretVersion
	// Labels carries operator-supplied, provider-native metadata (for
	// example Vault KV v2 custom_metadata, or AWS Secrets Manager tags).
	// It is safe with respect to the secret's VALUE, but it is NOT
	// sanitized or validated: the control plane persists it verbatim in
	// secrets.labels and returns it via GET /secrets, so anything an
	// operator has put into a provider's native metadata/tag fields
	// becomes catalog-visible to anyone who can read that endpoint.
	//
	// This is a trust-boundary crossing, not a bug: the provider's
	// metadata store and the Secrets Bridge catalog have different
	// audiences. Provider connectors MUST document this boundary at the
	// point they populate Labels, and MAY offer a per-connection
	// label-key allowlist so a deployment can restrict which keys are
	// permitted to cross into the catalog (see e.g. providers/vault's
	// ConfigLabelAllowlist). Connectors and callers must never promote
	// SecretValue content into Labels.
	Labels      map[string]string
	ContentType string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// Checksum is an opaque, non-reversible fingerprint of the value used
	// for change detection. It must not leak the value or allow recovery.
	Checksum string
}

// SecretVersion identifies a specific revision of a secret's value.
type SecretVersion struct {
	ID        string
	CreatedAt time.Time
}

// SecretValue carries the sensitive payload of a secret. Implementations
// and callers must treat instances of this type as confidential: do not log,
// stringify, marshal to telemetry, or include in error messages.
//
// Every generic way of turning a SecretValue into text or bytes yields
// "<redacted>": fmt (all verbs, through Format), encoding/json, anything
// that uses encoding.TextMarshaler or encoding.BinaryMarshaler (xml,
// gob, many YAML and cache clients) and log/slog (LogValue). The same
// holds when the value is a field, pointer field, slice or map element
// of something else being printed or marshalled. Callers that need the
// payload must read SecretValue.Bytes explicitly.
//
// Known gaps, which only a change to the exported shape could close:
//   - fmt's bad-verb path (%p on a SecretValue, %w outside Errorf or on
//     a non-error; go vet flags both) and a SecretValue held in an
//     UNEXPORTED struct field are printed by reflection, which skips
//     every method above and shows Bytes as a list of numbers.
//   - Printing or marshalling the Bytes field itself is not intercepted.
type SecretValue struct {
	// Bytes is the raw secret payload.
	Bytes []byte
	// ContentType describes the encoding of Bytes (e.g. "application/json",
	// "text/plain"). It is metadata, not a value, and may be logged.
	ContentType string
}

const redacted = "<redacted>"

// String intentionally hides the value to avoid accidental disclosure via
// fmt.Sprintf("%v", ...) or log statements. Callers that need the bytes
// must read SecretValue.Bytes explicitly.
func (SecretValue) String() string { return redacted }

// GoString prevents disclosure under the %#v verb.
func (SecretValue) GoString() string { return redacted }

// Format implements fmt.Formatter so every verb, flag and width (%d,
// %x, %08b, %U ...) prints "<redacted>". String and GoString alone only
// cover the string verbs; the rest fell through to the raw bytes.
func (SecretValue) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// MarshalJSON implements json.Marshaler. Without it encoding/json (and
// slog's JSONHandler) emitted Bytes as base64.
func (SecretValue) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler for encoders that prefer
// it (encoding/xml, slog's TextHandler, most YAML libraries).
func (SecretValue) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalBinary implements encoding.BinaryMarshaler, which encoding/gob
// and many cache and queue clients use to serialize a value.
func (SecretValue) MarshalBinary() ([]byte, error) { return []byte(redacted), nil }

// LogValue implements slog.LogValuer so a SecretValue handed to any slog
// handler resolves to "<redacted>" before the handler sees it.
func (SecretValue) LogValue() slog.Value { return slog.StringValue(redacted) }

// PutOptions controls how PutValue writes a new value.
type PutOptions struct {
	// Labels to attach to the new version. nil leaves labels unchanged.
	Labels map[string]string
	// ContentType describes the encoding of the value.
	ContentType string
	// IfMatch, when non-empty, requires the current version ID to match
	// before the write is accepted. Used for optimistic concurrency.
	IfMatch string
}

// ProviderScope restricts a ListMetadata call to a subset of secrets.
type ProviderScope struct {
	// Provider is the kind of backend to list within.
	Provider string
	// Scope is the namespace/mount/project to enumerate. Empty lists the
	// default scope of the provider, when the provider has one.
	Scope string
	// LabelSelector filters results to secrets whose labels match every
	// key/value pair. Empty matches everything.
	LabelSelector map[string]string
}

// Provider is the metadata/value-split abstraction over a secrets backend.
//
// Implementations must:
//   - return ErrNotFound when a ref does not resolve;
//   - never include secret values in returned errors or logs;
//   - honor ctx cancellation and deadlines.
type Provider interface {
	// GetMetadata returns metadata for a single secret without reading its
	// value. Cheap, side-effect free, safe to call frequently.
	GetMetadata(ctx context.Context, ref SecretRef) (SecretMetadata, error)

	// ListMetadata enumerates secrets within a scope. Implementations
	// should paginate internally and return a fully materialized slice.
	ListMetadata(ctx context.Context, scope ProviderScope) ([]SecretMetadata, error)

	// GetValue returns the sensitive value for a secret. Callers are
	// responsible for ensuring the returned SecretValue is not logged or
	// otherwise exposed.
	GetValue(ctx context.Context, ref SecretRef) (SecretValue, error)

	// PutValue writes a new value and returns the resulting version. The
	// provided SecretValue must not be retained by the implementation past
	// the call.
	PutValue(ctx context.Context, ref SecretRef, value SecretValue, opts PutOptions) (SecretVersion, error)
}

// Config carries provider-specific configuration. Concrete shape is decided
// by the Factory; the registry treats it opaquely.
type Config map[string]any

// Factory constructs a Provider from configuration.
type Factory func(ctx context.Context, cfg Config) (Provider, error)

// Registry maps provider kinds to Factory implementations. It is safe for
// concurrent use.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{factories: map[string]Factory{}}
}

// Register associates a Factory with a provider kind. Re-registering the
// same kind overwrites the previous Factory.
func (r *Registry) Register(kind string, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[kind] = f
}

// Build constructs a Provider for the given kind. It returns
// ErrProviderNotRegistered if no Factory has been registered.
func (r *Registry) Build(ctx context.Context, kind string, cfg Config) (Provider, error) {
	r.mu.RLock()
	f, ok := r.factories[kind]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotRegistered, kind)
	}
	return f(ctx, cfg)
}

// Kinds returns the registered provider kinds in unspecified order.
func (r *Registry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.factories))
	for k := range r.factories {
		out = append(out, k)
	}
	return out
}
