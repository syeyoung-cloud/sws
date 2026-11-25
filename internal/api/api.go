// Package api is what every service's part has in common: JSON calls, the services' refusals, and
// waiting for a member to answer an access request.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the HTTP client for every call; no call follows a redirect (a token goes to the
// address it was meant for and nowhere else).
var Client = &http.Client{
	Timeout: 60 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Error is a service's refusal.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s (%d)", e.Message, e.Status) }

// IsStatus tells whether err is a refusal with that status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// Call sends in as JSON (nil: no body) with the token as bearer ("" sends none), and decodes the
// answer into out (nil: ignored).
func Call(ctx context.Context, method, url, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Status: resp.StatusCode, Message: messageOf(b, resp.Status)}
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%s %s: the answer is not what was expected: %w", method, url, err)
		}
	}
	return nil
}

// messageOf finds the refusal's words in the forms the services use: {"error": "..."} (the drive,
// git-sts), {"detail": "..."} (Pulp), or {"field": ["..."]} (Pulp's validation).
func messageOf(b []byte, status string) string {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		if s := strings.TrimSpace(string(b)); s != "" && len(s) < 200 && !strings.HasPrefix(s, "<") {
			return s
		}
		return status
	}
	for _, k := range []string{"error", "detail", "message"} {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	var parts []string
	for k, v := range m {
		switch v := v.(type) {
		case string:
			parts = append(parts, k+": "+v)
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					parts = append(parts, k+": "+s)
				}
			}
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "; ")
	}
	return status
}

// Request is an access request a workload has made: a link for a member, and how often to ask
// after it.
type Request struct {
	ID       string
	URL      string
	Interval time.Duration
}

// Decision is how a request stands.
type Decision struct {
	State  string // pending, approved, declined
	Detail string // what was given, to say when approved
}

// Wait asks after a request every interval until it is decided, as in OAuth's device flow: the
// service keeps nothing open. A request that lapses or is withdrawn is a NotFound from check.
// When ctx ends first (the workload is stopped), withdraw is called with a fresh context.
func Wait(ctx context.Context, r Request, check func(context.Context) (Decision, error), withdraw func(context.Context) error) (Decision, error) {
	interval := r.Interval
	if interval < time.Second {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			wctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if withdraw != nil {
				_ = withdraw(wctx)
			}
			return Decision{}, errors.New("stopped; the request is withdrawn")
		case <-t.C:
		}
		d, err := check(ctx)
		if IsStatus(err, http.StatusNotFound) {
			return Decision{}, errors.New("the request lapsed or was withdrawn")
		}
		if err != nil {
			if ctx.Err() != nil {
				continue // the select above withdraws it
			}
			return Decision{}, err
		}
		switch d.State {
		case "pending":
			continue
		case "approved":
			return d, nil
		default:
			return d, fmt.Errorf("the request was %s", d.State)
		}
	}
}
