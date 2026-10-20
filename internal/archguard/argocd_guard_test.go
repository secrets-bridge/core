// Package archguard holds tests that keep architecture rules from
// regressing. It has no code of its own.
package archguard

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The Gateway is the only Secrets Bridge component that talks to Argo CD
// (secrets-bridge/gateway#13). core is imported by the api, worker,
// agent and controller, so an Argo CD client here would reach all of
// them. This guard fails if any non-test Go file in the module imports
// an Argo CD client or builds an Argo CD API path.

// forbiddenImport reports whether an import path names an Argo CD
// client: a package of our own called argocd, or the upstream modules.
func forbiddenImport(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "argocd") || strings.Contains(p, "argoproj") || strings.Contains(p, "argo-cd")
}

// argoCDAPIPaths are Argo CD REST API paths. Our own routes never use
// them.
var argoCDAPIPaths = []string{"/api/v1/applications", "/api/v1/stream/applications"}

// violations walks root and returns one line per non-test Go file that
// imports an Argo CD client or contains an Argo CD API path.
func violations(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbiddenImport(p) {
				out = append(out, rel+": imports "+p)
			}
		}
		lower := strings.ToLower(string(src))
		for _, ap := range argoCDAPIPaths {
			if strings.Contains(lower, ap) {
				out = append(out, rel+": contains the Argo CD API path "+ap)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// moduleRoot is the directory holding go.mod, above this package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func TestNoArgoCDClientInCore(t *testing.T) {
	root := moduleRoot(t)
	if v := violations(t, root); len(v) != 0 {
		t.Fatalf("only the Gateway may talk to Argo CD (secrets-bridge/gateway#13):\n  %s", strings.Join(v, "\n  "))
	}
}

// TestArgoCDGuardCatchesViolations keeps the guard honest: a file that
// imports an Argo CD client, or builds an Argo CD API path, is reported,
// and a test file is not.
func TestArgoCDGuardCatchesViolations(t *testing.T) {
	root := t.TempDir()
	write := func(name, src string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("client.go", "package x\n\nimport _ \"github.com/secrets-bridge/api/pkg/argocd\"\n")
	write("upstream.go", "package x\n\nimport _ \"github.com/argoproj/argo-cd/v2/pkg/apiclient\"\n")
	write("path.go", "package x\n\nconst p = \"/api/v1/applications/\" + \"x\"\n")
	write("fine_test.go", "package x\n\nimport _ \"github.com/secrets-bridge/api/pkg/argocd\"\n\nconst p = \"/api/v1/applications\"\n")
	write("clean.go", "package x\n\nconst q = \"/api/v1/gateways\"\n")
	got := violations(t, root)
	if len(got) != 3 {
		t.Fatalf("violations = %q; want client.go, upstream.go and path.go only", got)
	}
	for _, want := range []string{"client.go", "upstream.go", "path.go"} {
		found := false
		for _, v := range got {
			found = found || strings.HasPrefix(v, want+":")
		}
		if !found {
			t.Fatalf("violations = %q; %s not reported", got, want)
		}
	}
}
