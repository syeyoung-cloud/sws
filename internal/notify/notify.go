// Package notify is sws's part for notify: a workload sends notifications to the members who
// granted it, and asks members for a grant with a share request.
//
// Calls (notify's README):
//
//	POST   <url>/api/v1/notify          {title, body, link} → {recipients}
//	POST   <url>/api/v1/requests        {label} → {id, url, expires, interval}
//	GET    <url>/api/v1/requests/{id}   → {state, decidedBy, ...}
//	DELETE <url>/api/v1/requests/{id}
//	GET    <url>/api/v1/grants          → {issuer, subject, grants: [{member, label, created}]}
package notify

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/syeyoung-cloud/sws/internal/api"
	"github.com/syeyoung-cloud/sws/internal/identity"
)

type Notify struct {
	URL      string
	Audience string
	Identity identity.Source
}

func (n *Notify) call(ctx context.Context, method, path string, in, out any) error {
	tok, err := n.Identity.Token(ctx, n.Audience)
	if err != nil {
		return err
	}
	return api.Call(ctx, method, n.URL+path, tok, in, out)
}

// Message is one notification.
type Message struct {
	Title string `json:"title"`
	Body  string `json:"body,omitempty"`
	Link  string `json:"link,omitempty"`
}

// Send sends m to the members who granted this workload; it says how many it went to.
func (n *Notify) Send(ctx context.Context, m Message) (int, error) {
	var out struct {
		Recipients int `json:"recipients"`
	}
	err := n.call(ctx, http.MethodPost, "/api/v1/notify", m, &out)
	return out.Recipients, err
}

func (n *Notify) Ask(ctx context.Context, label string) (api.Request, error) {
	var out struct {
		ID       string `json:"id"`
		URL      string `json:"url"`
		Interval int    `json:"interval"`
	}
	if err := n.call(ctx, http.MethodPost, "/api/v1/requests", map[string]string{"label": label}, &out); err != nil {
		return api.Request{}, err
	}
	return api.Request{ID: out.ID, URL: out.URL, Interval: time.Duration(out.Interval) * time.Second}, nil
}

func (n *Notify) Check(ctx context.Context, id string) (api.Decision, error) {
	var out struct {
		State     string `json:"state"`
		DecidedBy string `json:"decidedBy"`
	}
	if err := n.call(ctx, http.MethodGet, "/api/v1/requests/"+url.PathEscape(id), nil, &out); err != nil {
		return api.Decision{}, err
	}
	detail := ""
	if out.State == "approved" {
		detail = out.DecidedBy + " will get this workload's notifications"
	}
	return api.Decision{State: out.State, Detail: detail}, nil
}

func (n *Notify) Withdraw(ctx context.Context, id string) error {
	return n.call(ctx, http.MethodDelete, "/api/v1/requests/"+url.PathEscape(id), nil, nil)
}

// Grant is a member who granted this workload.
type Grant struct {
	Member  string    `json:"member"`
	Label   string    `json:"label"`
	Created time.Time `json:"created"`
}

func (n *Notify) Grants(ctx context.Context) ([]Grant, error) {
	var out struct {
		Grants []Grant `json:"grants"`
	}
	err := n.call(ctx, http.MethodGet, "/api/v1/grants", nil, &out)
	return out.Grants, err
}
