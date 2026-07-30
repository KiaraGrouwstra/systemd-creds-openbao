package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kranzes/systemd-creds-openbao/go/internal/config"
	"github.com/kranzes/systemd-creds-openbao/go/internal/credserver"
)

type fakeReader struct {
	kv  map[string]map[string]any // "mount/path" -> data
	raw map[string]map[string]any // "path" -> data
}

func (f *fakeReader) Read(_ context.Context, ref config.SecretRef) (map[string]any, error) {
	from := f.kv
	if ref.Raw {
		from = f.raw
	}
	data, ok := from[ref.Location()]
	if !ok {
		return nil, errNotFound
	}
	return data, nil
}

var errNotFound = errors.New("secret not found")

func newResolver(t *testing.T, toml string, reader Reader) *Resolver {
	t.Helper()
	cfg, err := config.Parse([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	return NewResolver(cfg.Credentials, reader)
}

func TestResolveField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "myapp.service"
credential = "db-password"
path = "myapp/db"
field = "password"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/myapp/db": {"password": "hunter2"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "myapp.service", Credential: "db-password"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestResolveTemplates(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "systemd/{unit_name}"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/systemd/myapp": {"db-password": "hunter2"},
	}})

	got, gotPath, err := r.Resolve(context.Background(), credserver.Request{Unit: "myapp.service", Credential: "db-password"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
	if gotPath != "kv/systemd/myapp" {
		t.Errorf("got path %q, want %q", gotPath, "kv/systemd/myapp")
	}
}

func TestResolveFirstMatchWins(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "special.service"
path = "special"
field = "value"

[[credentials]]
unit = "*"
path = "fallback"
field = "value"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/special":  {"value": "from-special"},
		"kv/fallback": {"value": "from-fallback"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "special.service", Credential: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-special" {
		t.Errorf("got %q, want %q", got, "from-special")
	}

	got, _, err = r.Resolve(context.Background(), credserver.Request{Unit: "other.service", Credential: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-fallback" {
		t.Errorf("got %q, want %q", got, "from-fallback")
	}
}

func TestResolveNoMatchIsRefused(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "onlythis.service"
path = "p"
`, &fakeReader{})

	_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "other.service", Credential: "x"})
	if err == nil || !strings.Contains(err.Error(), "no credential rule matches") {
		t.Errorf("err = %v, want no-rule-matches error", err)
	}
}

func TestResolveMissingField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {"other": "x"},
	}})

	_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "missing"})
	if err == nil || !strings.Contains(err.Error(), `no field "missing"`) {
		t.Errorf("err = %v, want missing-field error", err)
	}
}

func TestResolveNullField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {"password": nil},
	}})

	// A present-but-null field must refuse the request: JSON-encoded it would
	// serve the four bytes "null", which a consumer reads as a real value.
	_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "password"})
	if err == nil || !strings.Contains(err.Error(), "null") {
		t.Errorf("err = %v, want null-field error", err)
	}
}

func TestResolveJSONFormat(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
backend = "raw"
path = "database/creds/myapp"
format = "json"
`, &fakeReader{raw: map[string]map[string]any{
		"database/creds/myapp": {"username": "u", "password": "p"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "myapp.service", Credential: "db"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if decoded["username"] != "u" || decoded["password"] != "p" {
		t.Errorf("decoded = %v", decoded)
	}
}

func TestResolveTemplateFormat(t *testing.T) {
	// The dynamic-database case: a DSN assembled from two fields of a
	// leased credential, which no combination of "field" and "json" can
	// produce.
	r := newResolver(t, `
[[credentials]]
unit = "*"
backend = "raw"
path = "database/creds/myapp"
format = "template"
template = "postgres://{{ .username }}:{{ .password }}@db.example:5432/appdb?sslmode=require"
`, &fakeReader{raw: map[string]map[string]any{
		"database/creds/myapp": {"username": "v-token-myapp-abc", "password": "hunter2"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "myapp.service", Credential: "dsn"})
	if err != nil {
		t.Fatal(err)
	}
	want := "postgres://v-token-myapp-abc:hunter2@db.example:5432/appdb?sslmode=require"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveTemplateEnvironmentFile(t *testing.T) {
	// The dominant case: a payload of KEY=value lines. A credential
	// cannot be consumed as an EnvironmentFile= directly (systemd loads
	// environment files before it sets credentials up), but a service
	// wrapper that sources $CREDENTIALS_DIRECTORY/<id> needs the payload
	// to be in exactly this shape.
	r := newResolver(t, `
[[credentials]]
unit = "restic-backups@*.service"
path = "restic/{instance}"
format = "template"
template = """
AWS_ACCESS_KEY_ID={{ .access_key }}
AWS_SECRET_ACCESS_KEY={{ .secret_key }}
RESTIC_REPOSITORY=s3:s3.example/backups
"""
`, &fakeReader{kv: map[string]map[string]any{
		"kv/restic/valkey": {"access_key": "AKIA", "secret_key": "s3cr3t"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{
		Unit:       "restic-backups@valkey.service",
		Credential: "env",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A TOML """ string drops the newline directly after the opening
	// delimiter, so the payload starts at the first variable -- no blank
	// leading line to confuse an environment-file parser.
	want := "AWS_ACCESS_KEY_ID=AKIA\nAWS_SECRET_ACCESS_KEY=s3cr3t\nRESTIC_REPOSITORY=s3:s3.example/backups\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveTemplateBase64Decode(t *testing.T) {
	// The "field" format only decodes values carrying a "base64:" prefix.
	// A convention that stores plain base64 needs to say so explicitly.
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "vars/{credential}"
format = "template"
template = "SMTP_PASSWORD={{ base64Decode .content }}"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/vars/smtp": {"content": base64.StdEncoding.EncodeToString([]byte("hunter2"))},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "smtp"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SMTP_PASSWORD=hunter2" {
		t.Errorf("got %q", got)
	}
}

func TestResolveTemplateMissingFieldIsAnError(t *testing.T) {
	// Without missingkey=error this renders "PASSWORD=<no value>" and the
	// consumer starts with a wrong secret instead of failing.
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
format = "template"
template = "PASSWORD={{ .password }}"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {"other": "x"},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "c"})
	if err == nil {
		t.Fatalf("Resolve succeeded with %q, want an error", got)
	}
	if !strings.Contains(err.Error(), "rendering template") {
		t.Errorf("err = %v, want a template rendering error", err)
	}
}

func TestResolveTemplateBadBase64IsAnError(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
format = "template"
template = "X={{ base64Decode .content }}"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {"content": "not base64!"},
	}})

	if _, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "c"}); err == nil {
		t.Fatal("Resolve succeeded, want an error")
	}
}

func TestResolveNonStringField(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {"port": json.Number("5432"), "flags": map[string]any{"a": true}},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "port"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "5432" {
		t.Errorf("number field = %q, want 5432", got)
	}

	got, _, err = r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "flags"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":true}` {
		t.Errorf("object field = %q, want JSON object", got)
	}
}

func TestResolveBase64Field(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "p"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/p": {
			"blob":   "base64:" + base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0xff}),
			"broken": "base64:!!!not-base64!!!",
		},
	}})

	got, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "blob"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x00, 0x01, 0xff}; !bytes.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// Invalid base64 refuses the credential instead of serving mangled bytes.
	if _, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "a.service", Credential: "broken"}); err == nil {
		t.Error("Resolve succeeded for invalid base64, want error")
	}
}

func TestResolveRejectsUncleanExpandedPath(t *testing.T) {
	r := newResolver(t, `
[[credentials]]
unit = "*"
path = "apps/{instance}"
`, &fakeReader{kv: map[string]map[string]any{
		"kv/apps/..": {"c": "x"},
		"kv/apps/":   {"c": "x"},
	}})

	// The instance name comes from whoever defines the unit: ".." must not
	// escape the rule's path prefix through URL normalization, and an empty
	// instance must not serve a path the rule never granted.
	for _, unit := range []string{"foo@...service", "plain.service"} {
		_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: unit, Credential: "c"})
		if err == nil || !strings.Contains(err.Error(), "segment") {
			t.Errorf("unit %s: err = %v, want unclean-path error", unit, err)
		}
	}

	r = newResolver(t, `
[[credentials]]
unit = "*"
mount = "{instance}"
path = "p"
`, &fakeReader{})
	_, _, err := r.Resolve(context.Background(), credserver.Request{Unit: "foo@...service", Credential: "c"})
	if err == nil || !strings.Contains(err.Error(), "segment") {
		t.Errorf("mount: err = %v, want unclean-path error", err)
	}
}

