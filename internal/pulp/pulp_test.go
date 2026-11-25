package pulp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyoung06/sws/internal/api"
)

type fixedToken string

func (f fixedToken) Token(context.Context, string) (string, error) { return string(f), nil }
func (fixedToken) Name() string                                    { return "fixed" }

func TestParseAsk(t *testing.T) {
	if a, err := ParseAsk("pypi/club:push"); err != nil || a.Distribution != "pypi/club" || a.Access != "push" {
		t.Fatal(a, err)
	}
	for _, bad := range []string{"pypi/club", ":pull", "x:read"} {
		if _, err := ParseAsk(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// A share request as pulp-workloads takes it; its refusals in DRF's forms are told in its words.
func TestRequest(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wl" {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"detail": "Authentication credentials were not provided."})
			return
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/pulp/api/v3/workload_share_requests/":
			json.NewDecoder(r.Body).Decode(&body)
			if len(body["ask"].([]any)) > 1 {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]any{"ask": []string{"Ask for 1 to 20 things."}})
				return
			}
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"id": "u-1", "url": "https://pulp.test/ui/approve/?id=u-1", "expires": "2026-11-26T10:00:00Z", "interval": 1})
		case r.Method == "GET" && r.URL.Path == "/pulp/api/v3/workload_share_requests/u-1/":
			json.NewEncoder(w).Encode(map[string]any{"state": "approved", "granted": []map[string]string{{"role": "x"}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	p := &Pulp{URL: srv.URL, Identity: fixedToken("wl")}
	r, err := p.Ask(context.Background(), "ci", []Ask{{"pypi/club", "push"}})
	if err != nil || r.ID != "u-1" || r.Interval != time.Second {
		t.Fatal(r, err)
	}
	if ask := body["ask"].([]any)[0].(map[string]any); ask["distribution"] != "pypi/club" || ask["access"] != "push" || body["label"] != "ci" {
		t.Fatal(body)
	}
	d, err := p.Check(context.Background(), "u-1")
	if err != nil || d.State != "approved" || d.Detail != "1 granted" {
		t.Fatal(d, err)
	}
	_, err = p.Ask(context.Background(), "", []Ask{{"a", "pull"}, {"b", "pull"}})
	if !api.IsStatus(err, 400) || !strings.Contains(err.Error(), "Ask for 1 to 20 things.") {
		t.Fatal(err)
	}
	_, err = (&Pulp{URL: srv.URL, Identity: fixedToken("x")}).Ask(context.Background(), "", []Ask{{"a", "pull"}})
	if !strings.Contains(err.Error(), "Authentication credentials were not provided.") {
		t.Fatal(err)
	}
}
