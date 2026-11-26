// Package pulp is sws's part for Pulp with workload identity (pulp-workloads): the workload's
// token is itself the credential, as a bearer token or as Basic auth with the user `__token__`;
// there is no exchange. sws asks for rights and hands out the token.
//
// Calls (pulp-workloads' README):
//
//	POST   <url>/pulp/api/v3/workload_share_requests/       {label, ask: [{distribution, access}]} → {id, url, expires, interval}
//	GET    <url>/pulp/api/v3/workload_share_requests/{id}/  → {state, granted, ...}
//	DELETE <url>/pulp/api/v3/workload_share_requests/{id}/
package pulp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/syeyoung-cloud/sws/internal/api"
	"github.com/syeyoung-cloud/sws/internal/identity"
)

type Pulp struct {
	URL      string
	Audience string
	Identity identity.Source
}

// Token is the credential: the workload's token made out to Pulp.
func (p *Pulp) Token(ctx context.Context) (string, error) {
	return p.Identity.Token(ctx, p.Audience)
}

func (p *Pulp) requests() string { return p.URL + "/pulp/api/v3/workload_share_requests/" }

// Ask is one thing asked for: a distribution (its base path) and pull or push.
type Ask struct {
	Distribution string `json:"distribution"`
	Access       string `json:"access"`
}

// ParseAsk reads "<base path>:pull" or "<base path>:push".
func ParseAsk(s string) (Ask, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || (s[i+1:] != "pull" && s[i+1:] != "push") {
		return Ask{}, fmt.Errorf("%q: ask as <distribution base path>:pull or :push", s)
	}
	return Ask{Distribution: s[:i], Access: s[i+1:]}, nil
}

func (p *Pulp) Ask(ctx context.Context, label string, asks []Ask) (api.Request, error) {
	tok, err := p.Token(ctx)
	if err != nil {
		return api.Request{}, err
	}
	var out struct {
		ID       string `json:"id"`
		URL      string `json:"url"`
		Interval int    `json:"interval"`
	}
	if err := api.Call(ctx, http.MethodPost, p.requests(), tok, map[string]any{"label": label, "ask": asks}, &out); err != nil {
		return api.Request{}, err
	}
	return api.Request{ID: out.ID, URL: out.URL, Interval: time.Duration(out.Interval) * time.Second}, nil
}

func (p *Pulp) Check(ctx context.Context, id string) (api.Decision, error) {
	tok, err := p.Token(ctx)
	if err != nil {
		return api.Decision{}, err
	}
	var out struct {
		State   string           `json:"state"`
		Granted []map[string]any `json:"granted"`
	}
	if err := api.Call(ctx, http.MethodGet, p.requests()+url.PathEscape(id)+"/", tok, nil, &out); err != nil {
		return api.Decision{}, err
	}
	detail := ""
	if out.State == "approved" {
		detail = fmt.Sprintf("%d granted", len(out.Granted))
	}
	return api.Decision{State: out.State, Detail: detail}, nil
}

func (p *Pulp) Withdraw(ctx context.Context, id string) error {
	tok, err := p.Token(ctx)
	if err != nil {
		return err
	}
	return api.Call(ctx, http.MethodDelete, p.requests()+url.PathEscape(id)+"/", tok, nil, nil)
}
