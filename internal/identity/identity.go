// Package identity gets the workload's own OIDC token for an audience, from the platform it runs
// on. Each call asks for a fresh one: tokens are short, and each service wants its own audience.
//
// Sources:
//   - kubernetes: the pod's service account token may create tokens for its own account
//     (TokenRequest), for any audience. A service account without that right fails here.
//   - github: a GitHub Actions job with `permissions: id-token: write`.
//   - metadata: a VM's metadata service (http://169.254.169.254/v1/token?audience=..., with the
//     header Metadata: true).
//   - command: any program that prints a token for the audience in $SWS_AUDIENCE (a VM's agent,
//     another cloud's metadata service).
//
// auto picks github when the job's variables are set, else kubernetes when a service account
// token is mounted, else the command when one is configured, else the metadata service when it
// answers.
package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Source gets a token made out to an audience.
type Source interface {
	Token(ctx context.Context, audience string) (string, error)
	Name() string
}

// KubeDir is where a pod's service account is mounted.
var KubeDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// New makes the source a configuration names. metadataURL is the metadata service's address for
// "metadata" ("" is the default, 169.254.169.254).
func New(source, command, metadataURL string) (Source, error) {
	switch source {
	case "github":
		return GitHub{}, nil
	case "kubernetes":
		return &Kubernetes{Dir: KubeDir}, nil
	case "command":
		return Command{Command: command}, nil
	case "metadata":
		return Metadata{URL: metadataURL}, nil
	case "auto", "":
		if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" {
			return GitHub{}, nil
		}
		if _, err := os.Stat(KubeDir + "/token"); err == nil {
			return &Kubernetes{Dir: KubeDir}, nil
		}
		if command != "" {
			return Command{Command: command}, nil
		}
		if metadataAnswers(metadataURL) {
			return Metadata{URL: metadataURL}, nil
		}
		return nil, errors.New("no workload identity here: not a GitHub Actions job with id-token: write, no service account token at " + KubeDir + ", no identity command configured, and no metadata service at " + orDefault(metadataURL))
	}
	return nil, fmt.Errorf("unknown identity source %q", source)
}

// Claims are the parts of a token sws shows; it never relies on them (the service verifies).
type Claims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Expiry  int64  `json:"exp"`
}

// Peek reads a token's claims without verifying it.
func Peek(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return Claims{}, fmt.Errorf("not a JWT: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(b, &c); err != nil {
		return Claims{}, fmt.Errorf("not a JWT: %w", err)
	}
	return c, nil
}

// Kubernetes asks the API server for a token of the pod's own service account.
type Kubernetes struct {
	Dir string
	// API is the API server's address; default from the pod's environment, else
	// https://kubernetes.default.svc.
	API string
	// Lifetime of the tokens it asks for; default one hour.
	Lifetime time.Duration
	// Pod to bind the tokens to; default the host's name. "-" binds to none.
	Pod string
}

func (k *Kubernetes) Name() string { return "kubernetes" }

func (k *Kubernetes) Token(ctx context.Context, audience string) (string, error) {
	own, err := os.ReadFile(k.Dir + "/token")
	if err != nil {
		return "", fmt.Errorf("no service account token: %w", err)
	}
	ownTok := strings.TrimSpace(string(own))
	c, err := Peek(ownTok)
	if err != nil {
		return "", fmt.Errorf("the service account token: %w", err)
	}
	// system:serviceaccount:<namespace>:<name>
	f := strings.Split(c.Subject, ":")
	if len(f) != 4 || f[0] != "system" || f[1] != "serviceaccount" {
		return "", fmt.Errorf("the service account token's subject is not a service account: %q", c.Subject)
	}
	ns, sa := f[2], f[3]
	api := k.API
	if api == "" {
		if h, p := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"); h != "" && p != "" {
			api = "https://" + joinHostPort(h, p)
		} else {
			api = "https://kubernetes.default.svc"
		}
	}
	client := http.DefaultClient
	if ca, err := os.ReadFile(k.Dir + "/ca.crt"); err == nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return "", errors.New("the service account's ca.crt holds no certificate")
		}
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	}
	life := k.Lifetime
	if life == 0 {
		life = time.Hour
	}
	pod := k.Pod
	if pod == "" {
		pod, _ = os.Hostname()
	}
	u := api + "/api/v1/namespaces/" + url.PathEscape(ns) + "/serviceaccounts/" + url.PathEscape(sa) + "/token"
	// Bound to this pod: the API server then stops honouring it with the pod (services that
	// verify by keys honour it until it expires, so it is short anyway).
	if pod != "" && pod != "-" {
		tok, status, err := k.request(ctx, client, u, ownTok, audience, life, pod)
		if status != http.StatusNotFound {
			return tok, err
		}
		// the host's name is no pod's (a container with a hostname of its own): unbound
	}
	tok, _, err := k.request(ctx, client, u, ownTok, audience, life, "")
	return tok, err
}

func (k *Kubernetes) request(ctx context.Context, client *http.Client, u, own, audience string, life time.Duration, pod string) (string, int, error) {
	spec := map[string]any{"audiences": []string{audience}, "expirationSeconds": int64(life / time.Second)}
	if pod != "" {
		spec["boundObjectRef"] = map[string]string{"apiVersion": "v1", "kind": "Pod", "name": pod}
	}
	body, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": spec})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+own)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("asking the cluster for a token: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var st struct{ Message string }
		_ = json.Unmarshal(b, &st)
		if resp.StatusCode == http.StatusForbidden {
			return "", resp.StatusCode, fmt.Errorf("the cluster refused a token: this service account may not create its own tokens (%s)", st.Message)
		}
		return "", resp.StatusCode, fmt.Errorf("the cluster refused a token: %d %s", resp.StatusCode, st.Message)
	}
	var out struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Status.Token == "" {
		return "", resp.StatusCode, errors.New("the cluster answered no token")
	}
	return out.Status.Token, resp.StatusCode, nil
}

func joinHostPort(h, p string) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]:" + p
	}
	return h + ":" + p
}

// GitHub asks the Actions runtime for the job's token.
type GitHub struct{}

func (GitHub) Name() string { return "github" }

func (GitHub) Token(ctx context.Context, audience string) (string, error) {
	base, bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if base == "" || bearer == "" {
		return "", errors.New("no GitHub Actions token here: the job needs `permissions: id-token: write`")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("asking GitHub for a token: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub refused a token: %s", resp.Status)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Value == "" {
		return "", errors.New("GitHub answered no token")
	}
	return out.Value, nil
}

// DefaultMetadataURL is where VMs ask for their identity token, the address clouds' metadata
// services use.
const DefaultMetadataURL = "http://169.254.169.254"

// Metadata asks a VM's metadata service for a token:
//
//	GET <url>/v1/token?audience=<audience>   (header Metadata: true)
//	→ {"token": "<JWT>", "expiresIn": 3599, "issuer": "...", "subject": "..."}
type Metadata struct {
	URL string
	// Timeout for each call; default 5 seconds (the service is on the machine's own link).
	Timeout time.Duration
}

func (Metadata) Name() string { return "metadata" }

func (m Metadata) Token(ctx context.Context, audience string) (string, error) {
	base := strings.TrimRight(m.URL, "/")
	if base == "" {
		base = DefaultMetadataURL
	}
	timeout := m.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/token?audience="+url.QueryEscape(audience), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata", "true")
	req.Header.Set("Accept", "application/json")
	// never through a proxy: the service refuses proxied requests, and the token is the machine's
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("asking the metadata service at %s for a token: %w", base, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the metadata service at %s refused a token: %s %s", base, resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("the metadata service at %s answered no token", base)
	}
	return out.Token, nil
}

// metadataAnswers tells whether a metadata service answers at all, quickly: for auto, where
// nothing else was found.
func metadataAnswers(base string) bool {
	if base == "" {
		base = DefaultMetadataURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "80")
		if u.Scheme == "https" {
			host = net.JoinHostPort(u.Hostname(), "443")
		}
	}
	c, err := net.DialTimeout("tcp", host, 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Command runs a program that prints a token for $SWS_AUDIENCE.
type Command struct{ Command string }

func (Command) Name() string { return "command" }

func (c Command) Token(ctx context.Context, audience string) (string, error) {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", c.Command)
	cmd.Env = append(os.Environ(), "SWS_AUDIENCE="+audience)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("the identity command: %w", err)
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		return "", errors.New("the identity command printed no token")
	}
	return tok, nil
}

func orDefault(u string) string {
	if u == "" {
		return DefaultMetadataURL
	}
	return u
}
