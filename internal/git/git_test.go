package git

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fixedToken string

func (f fixedToken) Token(_ context.Context, aud string) (string, error) {
	return string(f) + "@" + aud, nil
}
func (fixedToken) Name() string { return "fixed" }

func fakeSTS(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wl@https://sts.git.test" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
			return
		}
		switch r.URL.Path {
		case "/sts/token":
			var in struct{ Repo string }
			json.NewDecoder(r.Body).Decode(&in)
			if in.Repo != "alice/app" {
				w.WriteHeader(404)
				json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"user": "k8s.abc", "token": "fj-token", "validUntil": 1700000000})
		case "/sts/whoami":
			json.NewEncoder(w).Encode(map[string]string{"agent": "k8s.abc", "issuer": "https://k8s.test", "subject": "system:serviceaccount:c:x"})
		default:
			w.WriteHeader(404)
		}
	}))
}

// git's credential protocol: an answer for the forge's repos, the path passed as the repo (with or
// without .git); nothing at all for other hosts or plain http, so git asks its next helper.
func TestCredential(t *testing.T) {
	srv := fakeSTS(t)
	defer srv.Close()
	g := &Git{STS: srv.URL + "/sts", Audience: "https://sts.git.test", Host: "git.test", Identity: fixedToken("wl")}
	ask := func(in string) (string, string) {
		var out, warn bytes.Buffer
		if err := g.Credential(context.Background(), strings.NewReader(in), &out, &warn); err != nil {
			t.Fatal(err)
		}
		return out.String(), warn.String()
	}
	out, _ := ask("protocol=https\nhost=git.test\npath=alice/app.git\n\n")
	if out != "username=k8s.abc\npassword=fj-token\npassword_expiry_utc=1700000000\n" {
		t.Fatalf("%q", out)
	}
	for _, in := range []string{"protocol=https\nhost=github.com\npath=a/b\n", "protocol=http\nhost=git.test\npath=alice/app\n"} {
		if out, warn := ask(in); out != "" || warn != "" {
			t.Fatalf("answered %q %q for %q", out, warn, in)
		}
	}
	if out, warn := ask("protocol=https\nhost=git.test\npath=bob/x\n"); out != "" || !strings.Contains(warn, "may not see bob/x") {
		t.Fatalf("%q %q", out, warn)
	}
	if out, warn := ask("protocol=https\nhost=git.test\n"); out != "" || !strings.Contains(warn, "useHttpPath") {
		t.Fatalf("%q %q", out, warn)
	}
	w, err := g.Whoami(context.Background())
	if err != nil || w.Agent != "k8s.abc" {
		t.Fatal(w, err)
	}
}
