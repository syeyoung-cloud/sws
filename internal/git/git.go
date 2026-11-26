// Package git is sws's part for a Forgejo behind git-sts: git's credential helper, a token for a
// Forgejo CLI, asking a member for rights, and making repos.
//
// Calls (git-sts's README), all with the workload's token as bearer:
//
//	POST   <sts>/token                {repo}  → {user, token, validUntil} (one repo, one hour)
//	GET    <sts>/whoami               → {agent, issuer, subject}
//	POST   <sts>/repos                {owner, name, private} → {full_name, clone_url}
//	POST   <sts>/grant-requests       {owner, repos, permission, create, label} → {id, url, expires, interval}
//	GET    <sts>/grant-requests/{id}  → {state, agent}
//	DELETE <sts>/grant-requests/{id}
package git

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/syeyoung-cloud/sws/internal/api"
	"github.com/syeyoung-cloud/sws/internal/identity"
)

type Git struct {
	STS      string
	Audience string
	Host     string
	Identity identity.Source
}

func (g *Git) call(ctx context.Context, method, path string, in, out any) error {
	tok, err := g.Identity.Token(ctx, g.Audience)
	if err != nil {
		return err
	}
	return api.Call(ctx, method, g.STS+path, tok, in, out)
}

// Token is a Forgejo token for one repo ("owner/name").
type Token struct {
	User       string `json:"user"`
	Token      string `json:"token"`
	ValidUntil int64  `json:"validUntil"`
}

func (g *Git) Token(ctx context.Context, repo string) (Token, error) {
	repo = strings.TrimSuffix(strings.Trim(repo, "/"), ".git")
	var out Token
	err := g.call(ctx, http.MethodPost, "/token", map[string]string{"repo": repo}, &out)
	switch {
	case api.IsStatus(err, http.StatusForbidden):
		return Token{}, errors.New("this workload has no agent on the forge yet; ask for rights with `sws git request <owner> ...`")
	case api.IsStatus(err, http.StatusNotFound):
		return Token{}, fmt.Errorf("this workload may not see %s (ask with `sws git request`)", repo)
	}
	return out, err
}

type Who struct {
	Agent   string `json:"agent"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

func (g *Git) Whoami(ctx context.Context) (Who, error) {
	var out Who
	return out, g.call(ctx, http.MethodGet, "/whoami", nil, &out)
}

// CreateRepo makes a repo in an org (as the agent) or in a member's account (where granted), and
// returns its clone URL.
func (g *Git) CreateRepo(ctx context.Context, owner, name string, private bool) (string, error) {
	var out struct {
		CloneURL string `json:"clone_url"`
	}
	err := g.call(ctx, http.MethodPost, "/repos", map[string]any{"owner": owner, "name": name, "private": private}, &out)
	return out.CloneURL, err
}

// Ask makes a grant request.
func (g *Git) Ask(ctx context.Context, owner string, repos []string, permission string, create bool, label string) (api.Request, error) {
	if repos == nil {
		repos = []string{}
	}
	var out struct {
		ID       string `json:"id"`
		URL      string `json:"url"`
		Interval int    `json:"interval"`
	}
	err := g.call(ctx, http.MethodPost, "/grant-requests", map[string]any{"owner": owner, "repos": repos, "permission": permission, "create": create, "label": label}, &out)
	return api.Request{ID: out.ID, URL: out.URL, Interval: time.Duration(out.Interval) * time.Second}, err
}

func (g *Git) Check(ctx context.Context, id string) (api.Decision, error) {
	var out struct {
		State string `json:"state"`
		Agent string `json:"agent"`
	}
	if err := g.call(ctx, http.MethodGet, "/grant-requests/"+url.PathEscape(id), nil, &out); err != nil {
		return api.Decision{}, err
	}
	detail := ""
	if out.State == "approved" {
		detail = "granted to " + out.Agent
	}
	return api.Decision{State: out.State, Detail: detail}, nil
}

func (g *Git) Withdraw(ctx context.Context, id string) error {
	return g.call(ctx, http.MethodDelete, "/grant-requests/"+url.PathEscape(id), nil, nil)
}

// Setup points git at sws for the forge's host, with the repo path passed along (each token is
// good for one repo). helper is the command git runs ("sws git credential" with sws's path).
func (g *Git) Setup(helper string) error {
	prefix := "credential.https://" + g.Host
	steps := [][]string{
		{"config", "--global", "--replace-all", prefix + ".helper", ""}, // clears helpers set before for this host
		{"config", "--global", "--add", prefix + ".helper", "!" + helper},
		{"config", "--global", prefix + ".useHttpPath", "true"},
	}
	for _, args := range steps {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

// Credential answers git's credential helper protocol for "get": user and password for the repo
// git asks about. For any other host it answers nothing, so git goes on to its other helpers.
// Store and erase need nothing: a new token is had each time.
func (g *Git) Credential(ctx context.Context, in io.Reader, out io.Writer, warn io.Writer) error {
	asked := map[string]string{}
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			asked[k] = v
		}
	}
	if asked["protocol"] != "https" || asked["host"] != g.Host {
		return nil
	}
	if asked["path"] == "" {
		fmt.Fprintln(warn, "sws: git did not say which repo; run `sws git setup` (it sets credential.useHttpPath)")
		return nil
	}
	t, err := g.Token(ctx, asked["path"])
	if err != nil {
		fmt.Fprintln(warn, "sws:", err)
		return nil
	}
	_, err = fmt.Fprintf(out, "username=%s\npassword=%s\npassword_expiry_utc=%d\n", t.User, t.Token, t.ValidUntil)
	return err
}
