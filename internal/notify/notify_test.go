package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyoung06/sws/internal/api"
)

type fixedToken string

func (f fixedToken) Token(_ context.Context, aud string) (string, error) {
	return string(f) + ":" + aud, nil
}
func (fixedToken) Name() string { return "fixed" }

func TestNotify(t *testing.T) {
	var sent map[string]any
	checks := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wl:https://notify.test" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"detail": "The token isn't one notify accepts."})
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/notify":
			json.NewDecoder(r.Body).Decode(&sent)
			if sent["link"] == "http://bad" {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"detail": "A link is an https address on example.org."})
				return
			}
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(map[string]int{"recipients": 2})
		case "POST /api/v1/requests":
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"id": "r1", "url": "https://notify.test/approve?id=r1", "interval": 1})
		case "GET /api/v1/requests/r1":
			checks++
			state := "pending"
			if checks > 1 {
				state = "approved"
			}
			json.NewEncoder(w).Encode(map[string]string{"state": state, "decidedBy": "alice"})
		case "GET /api/v1/grants":
			json.NewEncoder(w).Encode(map[string]any{"grants": []map[string]any{{"member": "alice", "label": "claude", "created": "2026-11-26T01:00:00Z"}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	n := &Notify{URL: srv.URL, Audience: "https://notify.test", Identity: fixedToken("wl")}
	ctx := context.Background()
	if got, err := n.Send(ctx, Message{Title: "t", Body: "b"}); err != nil || got != 2 || sent["title"] != "t" {
		t.Fatalf("send: %d %v %v", got, err, sent)
	}
	if _, ok := sent["link"]; ok {
		t.Error("an empty link was sent")
	}
	if _, err := n.Send(ctx, Message{Title: "t", Link: "http://bad"}); err == nil || err.Error() != "A link is an https address on example.org. (400)" {
		t.Errorf("refusal: %v", err)
	}
	r, err := n.Ask(ctx, "claude")
	if err != nil || r.URL != "https://notify.test/approve?id=r1" || r.Interval != time.Second {
		t.Fatalf("ask: %+v %v", r, err)
	}
	d, err := api.Wait(ctx, r, func(c context.Context) (api.Decision, error) { return n.Check(c, r.ID) }, nil)
	if err != nil || d.State != "approved" {
		t.Fatalf("wait: %+v %v", d, err)
	}
	gs, err := n.Grants(ctx)
	if err != nil || len(gs) != 1 || gs[0].Member != "alice" {
		t.Fatalf("grants: %+v %v", gs, err)
	}
}
