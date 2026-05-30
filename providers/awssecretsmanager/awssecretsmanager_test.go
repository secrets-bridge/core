package awssecretsmanager

import (
	"context"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/secrets-bridge/core/providers"
)

// fakeClient implements awsSMClient with hand-set responses, so tests
// can exercise the adapter without hitting AWS.
type fakeClient struct {
	describeResp *secretsmanager.DescribeSecretOutput
	describeErr  error
	listPages    []*secretsmanager.ListSecretsOutput
	listIdx      int
	listErr      error
	getResp      *secretsmanager.GetSecretValueOutput
	getErr       error
	putResp      *secretsmanager.PutSecretValueOutput
	putErr       error
	createResp   *secretsmanager.CreateSecretOutput
	createErr    error

	lastDescribe *secretsmanager.DescribeSecretInput
	lastGet      *secretsmanager.GetSecretValueInput
	lastPut      *secretsmanager.PutSecretValueInput
	lastCreate   *secretsmanager.CreateSecretInput
}

func (f *fakeClient) DescribeSecret(_ context.Context, in *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	f.lastDescribe = in
	return f.describeResp, f.describeErr
}
func (f *fakeClient) ListSecrets(_ context.Context, _ *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listIdx >= len(f.listPages) {
		return &secretsmanager.ListSecretsOutput{}, nil
	}
	out := f.listPages[f.listIdx]
	f.listIdx++
	return out, nil
}
func (f *fakeClient) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.lastGet = in
	return f.getResp, f.getErr
}
func (f *fakeClient) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.lastPut = in
	return f.putResp, f.putErr
}
func (f *fakeClient) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	f.lastCreate = in
	return f.createResp, f.createErr
}

func newTestProvider(c *fakeClient) *Provider { return &Provider{client: c} }

func TestRegister(t *testing.T) {
	r := providers.NewRegistry()
	Register(r)
	kinds := r.Kinds()
	if len(kinds) != 1 || kinds[0] != Kind {
		t.Fatalf("Register: expected one kind %q, got %v", Kind, kinds)
	}
}

func TestGetMetadata_Found(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	fc := &fakeClient{
		describeResp: &secretsmanager.DescribeSecretOutput{
			Name:            awsv2.String("app/db"),
			CreatedDate:     &now,
			LastChangedDate: &now,
			VersionIdsToStages: map[string][]string{
				"v-current":  {"AWSCURRENT"},
				"v-previous": {"AWSPREVIOUS"},
			},
			Tags: []smtypes.Tag{
				{Key: awsv2.String("env"), Value: awsv2.String("prod")},
			},
		},
	}
	p := newTestProvider(fc)
	ref := providers.SecretRef{Provider: Kind, Name: "app/db"}

	got, err := p.GetMetadata(t.Context(), ref)
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if got.Version.ID != "v-current" {
		t.Fatalf("Version.ID: got %q want v-current", got.Version.ID)
	}
	if got.Labels["env"] != "prod" {
		t.Fatalf("Labels: %v", got.Labels)
	}
	if !got.CreatedAt.Equal(now) {
		t.Fatalf("CreatedAt: got %v want %v", got.CreatedAt, now)
	}
	if got.Checksum != "" {
		t.Fatal("Checksum must stay empty when populated from DescribeSecret " +
			"— DescribeSecret does not expose a content hash and the agent " +
			"is the one that fills this after GetValue.")
	}
}

func TestGetMetadata_NotFound(t *testing.T) {
	fc := &fakeClient{describeErr: &smtypes.ResourceNotFoundException{}}
	p := newTestProvider(fc)
	ref := providers.SecretRef{Provider: Kind, Name: "missing"}

	_, err := p.GetMetadata(t.Context(), ref)
	if !errors.Is(err, providers.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListMetadata_Paginates(t *testing.T) {
	fc := &fakeClient{
		listPages: []*secretsmanager.ListSecretsOutput{
			{
				SecretList: []smtypes.SecretListEntry{
					{Name: awsv2.String("a")},
					{Name: awsv2.String("b")},
				},
				NextToken: awsv2.String("page-2"),
			},
			{
				SecretList: []smtypes.SecretListEntry{
					{Name: awsv2.String("c")},
				},
				// No NextToken: end of pagination.
			},
		},
	}
	p := newTestProvider(fc)

	got, err := p.ListMetadata(t.Context(), providers.ProviderScope{Scope: "default"})
	if err != nil {
		t.Fatalf("ListMetadata: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries across pages, got %d: %+v", len(got), got)
	}
	wantNames := []string{"a", "b", "c"}
	for i, w := range wantNames {
		if got[i].Ref.Name != w {
			t.Errorf("entry[%d].Ref.Name: got %q want %q", i, got[i].Ref.Name, w)
		}
		if got[i].Ref.Provider != Kind {
			t.Errorf("entry[%d].Ref.Provider: got %q want %q", i, got[i].Ref.Provider, Kind)
		}
		if got[i].Ref.Scope != "default" {
			t.Errorf("entry[%d].Ref.Scope: got %q want %q", i, got[i].Ref.Scope, "default")
		}
	}
}

func TestGetValue_StringSecret(t *testing.T) {
	fc := &fakeClient{
		getResp: &secretsmanager.GetSecretValueOutput{
			SecretString: awsv2.String("super-token"),
			VersionId:    awsv2.String("v1"),
		},
	}
	p := newTestProvider(fc)
	ref := providers.SecretRef{Provider: Kind, Name: "x", Version: "v1"}

	val, err := p.GetValue(t.Context(), ref)
	if err != nil {
		t.Fatalf("GetValue: %v", err)
	}
	if string(val.Bytes) != "super-token" {
		t.Fatalf("bytes: %q", val.Bytes)
	}
	if val.ContentType != "text/plain" {
		t.Fatalf("ContentType: %q", val.ContentType)
	}
	// Confirm version pin propagated into the request — important for
	// reproducible reads during sync.
	if fc.lastGet.VersionId == nil || *fc.lastGet.VersionId != "v1" {
		t.Fatalf("Version pin not propagated: %+v", fc.lastGet)
	}
}

func TestGetValue_BinarySecret(t *testing.T) {
	payload := []byte{0x00, 0xff, 0x42}
	fc := &fakeClient{
		getResp: &secretsmanager.GetSecretValueOutput{SecretBinary: payload},
	}
	p := newTestProvider(fc)
	val, err := p.GetValue(t.Context(), providers.SecretRef{Provider: Kind, Name: "b"})
	if err != nil {
		t.Fatalf("GetValue: %v", err)
	}
	if string(val.Bytes) != string(payload) {
		t.Fatalf("bytes: %v", val.Bytes)
	}
	if val.ContentType != "application/octet-stream" {
		t.Fatalf("ContentType: %q", val.ContentType)
	}
}

func TestGetValue_NotFound(t *testing.T) {
	fc := &fakeClient{getErr: &smtypes.ResourceNotFoundException{}}
	p := newTestProvider(fc)
	_, err := p.GetValue(t.Context(), providers.SecretRef{Provider: Kind, Name: "gone"})
	if !errors.Is(err, providers.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPutValue_UpdateExisting(t *testing.T) {
	fc := &fakeClient{
		putResp: &secretsmanager.PutSecretValueOutput{VersionId: awsv2.String("v-new")},
	}
	p := newTestProvider(fc)

	ver, err := p.PutValue(t.Context(),
		providers.SecretRef{Provider: Kind, Name: "x"},
		providers.SecretValue{Bytes: []byte("hello")},
		providers.PutOptions{},
	)
	if err != nil {
		t.Fatalf("PutValue: %v", err)
	}
	if ver.ID != "v-new" {
		t.Fatalf("Version.ID: %q", ver.ID)
	}
	if fc.lastCreate != nil {
		t.Fatal("CreateSecret should not have been called when Put succeeded")
	}
}

func TestPutValue_FallbackCreateOnNotFound(t *testing.T) {
	fc := &fakeClient{
		putErr:     &smtypes.ResourceNotFoundException{},
		createResp: &secretsmanager.CreateSecretOutput{VersionId: awsv2.String("v-init")},
	}
	p := newTestProvider(fc)

	ver, err := p.PutValue(t.Context(),
		providers.SecretRef{Provider: Kind, Name: "new"},
		providers.SecretValue{Bytes: []byte("hello")},
		providers.PutOptions{Labels: map[string]string{"env": "prod"}},
	)
	if err != nil {
		t.Fatalf("PutValue: %v", err)
	}
	if ver.ID != "v-init" {
		t.Fatalf("Version.ID: %q", ver.ID)
	}
	if fc.lastCreate == nil {
		t.Fatal("CreateSecret was not called after Put returned not-found")
	}
	if len(fc.lastCreate.Tags) != 1 || *fc.lastCreate.Tags[0].Key != "env" {
		t.Fatalf("Tags not propagated to CreateSecret: %+v", fc.lastCreate.Tags)
	}
}

func TestPutValue_PropagatesNonRecoverableError(t *testing.T) {
	boom := errors.New("aws boom")
	fc := &fakeClient{putErr: boom}
	p := newTestProvider(fc)

	_, err := p.PutValue(t.Context(),
		providers.SecretRef{Provider: Kind, Name: "x"},
		providers.SecretValue{Bytes: []byte("hi")},
		providers.PutOptions{},
	)
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped %v, got %v", boom, err)
	}
	if fc.lastCreate != nil {
		t.Fatal("CreateSecret must NOT be attempted on a non-not-found Put error")
	}
}

// listFixture returns a single page with the three example secrets used
// across the filter tests below. Each carries a distinct tag set so the
// filters land on the right rows.
func listFixture() []*secretsmanager.ListSecretsOutput {
	return []*secretsmanager.ListSecretsOutput{
		{
			SecretList: []smtypes.SecretListEntry{
				{
					Name: awsv2.String("team-alpha/uat/db"),
					Tags: []smtypes.Tag{
						{Key: awsv2.String("EnvironmentName"), Value: awsv2.String("tenant-a-uat")},
						{Key: awsv2.String("Project"), Value: awsv2.String("alpha")},
					},
				},
				{
					Name: awsv2.String("team-alpha/prod/db"),
					Tags: []smtypes.Tag{
						{Key: awsv2.String("EnvironmentName"), Value: awsv2.String("tenant-a-prod")},
						{Key: awsv2.String("Project"), Value: awsv2.String("alpha")},
					},
				},
				{
					Name: awsv2.String("team-beta/uat/db"),
					Tags: []smtypes.Tag{
						{Key: awsv2.String("EnvironmentName"), Value: awsv2.String("tenant-a-uat")},
						{Key: awsv2.String("Project"), Value: awsv2.String("beta")},
					},
				},
			},
		},
	}
}

func TestListMetadata_TagFilterDropsNonMatchingRows(t *testing.T) {
	fc := &fakeClient{listPages: listFixture()}
	p := &Provider{
		client:    fc,
		tagFilter: map[string]string{"EnvironmentName": "tenant-a-uat"},
	}

	got, err := p.ListMetadata(t.Context(), providers.ProviderScope{Scope: "default"})
	if err != nil {
		t.Fatalf("ListMetadata: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 UAT rows, got %d: %+v", len(got), refNames(got))
	}
	for _, m := range got {
		if m.Labels["EnvironmentName"] != "tenant-a-uat" {
			t.Errorf("leaked non-UAT row %q with EnvironmentName=%q", m.Ref.Name, m.Labels["EnvironmentName"])
		}
	}
}

func TestListMetadata_ScopeLabelSelectorANDsWithTagFilter(t *testing.T) {
	fc := &fakeClient{listPages: listFixture()}
	p := &Provider{
		client:    fc,
		tagFilter: map[string]string{"EnvironmentName": "tenant-a-uat"},
	}

	got, err := p.ListMetadata(t.Context(), providers.ProviderScope{
		Scope:         "default",
		LabelSelector: map[string]string{"Project": "beta"},
	})
	if err != nil {
		t.Fatalf("ListMetadata: %v", err)
	}
	if len(got) != 1 || got[0].Ref.Name != "team-beta/uat/db" {
		t.Fatalf("AND of tagFilter+LabelSelector should leave only team-beta/uat/db, got %v", refNames(got))
	}
}

func TestListMetadata_NoFiltersReturnsEverything(t *testing.T) {
	fc := &fakeClient{listPages: listFixture()}
	p := newTestProvider(fc)

	got, err := p.ListMetadata(t.Context(), providers.ProviderScope{Scope: "default"})
	if err != nil {
		t.Fatalf("ListMetadata: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("no filters → expected 3 rows, got %d: %v", len(got), refNames(got))
	}
}

func TestReadTagFilter_AcceptsBothShapes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want map[string]string
	}{
		{"nil", nil, nil},
		{"empty-string-map", map[string]string{}, nil},
		{"empty-any-map", map[string]any{}, nil},
		{"string-map", map[string]string{"EnvironmentName": "uat"}, map[string]string{"EnvironmentName": "uat"}},
		{"any-map-of-strings", map[string]any{"EnvironmentName": "uat"}, map[string]string{"EnvironmentName": "uat"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readTagFilter(c.in)
			if err != nil {
				t.Fatalf("readTagFilter: %v", err)
			}
			if !mapsEqual(got, c.want) {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestReadTagFilter_RejectsBadShapes(t *testing.T) {
	cases := []struct {
		name string
		in   any
	}{
		{"non-string-value", map[string]any{"k": 42}},
		{"wrong-outer-type", []string{"k", "v"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := readTagFilter(c.in); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func refNames(in []providers.SecretMetadata) []string {
	out := make([]string, len(in))
	for i, m := range in {
		out[i] = m.Ref.Name
	}
	return out
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
