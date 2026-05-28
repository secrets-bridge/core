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

// SecretMetadata describes a secret without exposing its value. Anything in
// this struct is considered non-sensitive and is safe to log and cache.
type SecretMetadata struct {
	Ref         SecretRef
	Version     SecretVersion
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
type SecretValue struct {
	// Bytes is the raw secret payload.
	Bytes []byte
	// ContentType describes the encoding of Bytes (e.g. "application/json",
	// "text/plain"). It is metadata, not a value, and may be logged.
	ContentType string
}

// String intentionally hides the value to avoid accidental disclosure via
// fmt.Sprintf("%v", ...) or log statements. Callers that need the bytes
// must read SecretValue.Bytes explicitly.
func (SecretValue) String() string { return "<redacted>" }

// GoString prevents disclosure under the %#v verb.
func (SecretValue) GoString() string { return "<redacted>" }

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
