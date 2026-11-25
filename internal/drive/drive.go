// Package drive is sws's part for the drive: asking a member to share a folder, listing what is
// shared, and turning the workload's token into an SSH certificate (kept, with an ssh config entry,
// and renewed when ssh connects) or an SMB password.
//
// Calls (the drive's docs/using-workloads.md):
//
//	POST   <url>/api/v1/share-requests      {label, readOnly} → {id, url, expires, interval}
//	GET    <url>/api/v1/share-requests/{id} → {state, owner, ...}
//	DELETE <url>/api/v1/share-requests/{id}
//	GET    <url>/api/v1/workload/grants     → {grants: [{id, name, owner, readOnly, expires}]}
//	POST   <url>/api/v1/sts/token           {token, owner, ssh: {publicKey}} | {token, owner, smb: true}
package drive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cyoung06/sws/internal/api"
	"github.com/cyoung06/sws/internal/identity"
)

type Drive struct {
	URL      string
	Audience string
	Identity identity.Source
	// State is the folder credentials are kept in (one folder per owner below it).
	State string
	// Renew is how long before a certificate runs out a new one is had; default 10 minutes.
	Renew time.Duration
	Now   func() time.Time
}

func (d *Drive) token(ctx context.Context) (string, error) {
	return d.Identity.Token(ctx, d.Audience)
}

func (d *Drive) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Grant is a folder shared with this workload.
type Grant struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Owner    string `json:"owner"`
	ReadOnly bool   `json:"readOnly"`
	Expires  *int64 `json:"expires"`
}

func (d *Drive) Grants(ctx context.Context) ([]Grant, error) {
	tok, err := d.token(ctx)
	if err != nil {
		return nil, err
	}
	var out struct {
		Grants []Grant `json:"grants"`
	}
	if err := api.Call(ctx, http.MethodGet, d.URL+"/api/v1/workload/grants", tok, nil, &out); err != nil {
		return nil, err
	}
	return out.Grants, nil
}

// Ask makes a share request.
func (d *Drive) Ask(ctx context.Context, label string, readOnly bool) (api.Request, error) {
	tok, err := d.token(ctx)
	if err != nil {
		return api.Request{}, err
	}
	var out struct {
		ID       string `json:"id"`
		URL      string `json:"url"`
		Interval int    `json:"interval"`
	}
	if err := api.Call(ctx, http.MethodPost, d.URL+"/api/v1/share-requests", tok, map[string]any{"label": label, "readOnly": readOnly}, &out); err != nil {
		return api.Request{}, err
	}
	return api.Request{ID: out.ID, URL: out.URL, Interval: time.Duration(out.Interval) * time.Second}, nil
}

// Check is how a share request stands; approved says who shared.
func (d *Drive) Check(ctx context.Context, id string) (api.Decision, error) {
	tok, err := d.token(ctx)
	if err != nil {
		return api.Decision{}, err
	}
	var out struct {
		State    string `json:"state"`
		Owner    string `json:"owner"`
		ReadOnly bool   `json:"readOnly"`
	}
	if err := api.Call(ctx, http.MethodGet, d.URL+"/api/v1/share-requests/"+url.PathEscape(id), tok, nil, &out); err != nil {
		return api.Decision{}, err
	}
	detail := ""
	if out.State == "approved" {
		detail = "shared by " + out.Owner
	}
	return api.Decision{State: out.State, Detail: detail}, nil
}

// Withdraw takes a share request back.
func (d *Drive) Withdraw(ctx context.Context, id string) error {
	tok, err := d.token(ctx)
	if err != nil {
		return err
	}
	return api.Call(ctx, http.MethodDelete, d.URL+"/api/v1/share-requests/"+url.PathEscape(id), tok, nil, nil)
}

// SMB is a password for the SMB share, acting for owner.
type SMB struct {
	User       string `json:"user"`
	Password   string `json:"password"`
	ValidUntil int64  `json:"validUntil"`
	Share      string `json:"share"`
}

func (d *Drive) SMB(ctx context.Context, owner string) (SMB, error) {
	tok, err := d.token(ctx)
	if err != nil {
		return SMB{}, err
	}
	var out SMB
	err = api.Call(ctx, http.MethodPost, d.URL+"/api/v1/sts/token", "", map[string]any{"token": tok, "owner": owner, "smb": true}, &out)
	return out, explain(err, owner)
}

func explain(err error, owner string) error {
	switch {
	case api.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("%s shares nothing with this workload (ask with `sws drive request`)", owner)
	case api.IsStatus(err, http.StatusTooManyRequests):
		return fmt.Errorf("too many credentials for %s are live; one frees up when it runs out", owner)
	}
	return err
}

// ownerName is what a member's name may be here: it becomes a folder and an ssh host alias.
var ownerName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,63}$`)

// Alias is the ssh host alias for owner's folders.
func Alias(owner string) string { return "drive-" + owner }

// OwnerOfAlias is the owner an alias names.
func OwnerOfAlias(alias string) (string, bool) {
	o, ok := strings.CutPrefix(alias, "drive-")
	return o, ok && ownerName.MatchString(o)
}

// SSH is a kept certificate.
type SSH struct {
	Alias      string
	User       string
	Host       string
	Port       int
	Path       string
	ValidUntil time.Time
	Renewed    bool
}

// EnsureSSH makes sure a certificate acting for owner is kept and has more than Renew left,
// getting a new one when not, and writes the ssh config entry for it. The key stays; only the
// certificate is renewed. Files are written whole and renamed into place, so a second sws doing
// the same at once leaves one or the other, both good.
func (d *Drive) EnsureSSH(ctx context.Context, owner string) (SSH, error) {
	if !ownerName.MatchString(owner) {
		return SSH{}, fmt.Errorf("%q is not a member's name", owner)
	}
	dir := filepath.Join(d.State, "drive", owner)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return SSH{}, err
	}
	keyFile, certFile, confFile := filepath.Join(dir, "key"), filepath.Join(dir, "key-cert.pub"), filepath.Join(dir, "ssh_config")
	renew := d.Renew
	if renew == 0 {
		renew = 10 * time.Minute
	}
	if c, err := readCert(certFile); err == nil {
		until := time.Unix(int64(c.ValidBefore), 0)
		if until.Sub(d.now()) > renew && len(c.ValidPrincipals) == 1 {
			if conf, err := os.ReadFile(confFile); err == nil {
				host, port := hostPortOf(string(conf))
				return SSH{Alias: Alias(owner), User: c.ValidPrincipals[0], Host: host, Port: port, Path: "/root/shared", ValidUntil: until}, nil
			}
		}
	}
	pub, err := ensureKey(keyFile)
	if err != nil {
		return SSH{}, err
	}
	tok, err := d.token(ctx)
	if err != nil {
		return SSH{}, err
	}
	var out struct {
		User        string `json:"user"`
		Certificate string `json:"certificate"`
		ValidUntil  int64  `json:"validUntil"`
		Host        string `json:"host"`
		Port        int    `json:"port"`
		Path        string `json:"path"`
	}
	err = api.Call(ctx, http.MethodPost, d.URL+"/api/v1/sts/token", "", map[string]any{"token": tok, "owner": owner, "ssh": map[string]string{"publicKey": pub}}, &out)
	if err != nil {
		return SSH{}, explain(err, owner)
	}
	cert := strings.TrimSpace(out.Certificate) // one line: a second, empty one is refused by ssh-keygen
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert)); err != nil {
		return SSH{}, fmt.Errorf("the drive answered no certificate: %w", err)
	}
	if out.Host == "" || out.Port == 0 || out.User == "" {
		return SSH{}, errors.New("the drive did not say where to sign in")
	}
	conf := fmt.Sprintf("# written by sws for %s's folders on the drive; renewed when ssh connects\nHost %s\n  HostName %s\n  Port %d\n  User %s\n  IdentityFile %s\n  CertificateFile %s\n  IdentitiesOnly yes\n",
		owner, Alias(owner), out.Host, out.Port, out.User, quote(keyFile), quote(certFile))
	if err := writeFile(certFile, []byte(cert+"\n"), 0o600); err != nil {
		return SSH{}, err
	}
	if err := writeFile(confFile, []byte(conf), 0o600); err != nil {
		return SSH{}, err
	}
	return SSH{Alias: Alias(owner), User: out.User, Host: out.Host, Port: out.Port, Path: out.Path, ValidUntil: time.Unix(out.ValidUntil, 0), Renewed: true}, nil
}

func quote(p string) string {
	if strings.ContainsAny(p, " \t\"") {
		return `"` + strings.ReplaceAll(p, `"`, `\"`) + `"`
	}
	return p
}

func hostPortOf(conf string) (string, int) {
	var host string
	var port int
	for _, l := range strings.Split(conf, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "HostName" {
			host = f[1]
		}
		if len(f) == 2 && f[0] == "Port" {
			port, _ = strconv.Atoi(f[1])
		}
	}
	return host, port
}

func readCert(path string) (*ssh.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, err
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("not a certificate")
	}
	return c, nil
}

// ensureKey makes the ed25519 key once and returns its public half in authorized_keys form.
func ensureKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		k, err := ssh.ParseRawPrivateKey(b)
		if err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		signer, err := ssh.NewSignerFromKey(k)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "sws drive")
	if err != nil {
		return "", err
	}
	if err := writeFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", err
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	if err := writeFile(path+".pub", []byte(line+"\n"), 0o644); err != nil {
		return "", err
	}
	return line, nil
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// SSHConfigBlock is what `sws drive setup` puts in ~/.ssh/config: before connecting to a
// drive-<owner> alias, ssh runs `sws drive ensure`, which renews the certificate when it needs to,
// and then reads the entries sws keeps.
func SSHConfigBlock(self, state string) string {
	inc := filepath.Join(state, "drive", "*", "ssh_config")
	// "Match all" ends the condition, so lines after the block that belong to no Host apply to all,
	// as they did before it was put there.
	return fmt.Sprintf("%s\nMatch host \"drive-*\" exec \"%s drive ensure %%n\"\n  Include %s\nMatch all\n%s\n", BlockStart, self, quote(inc), BlockEnd)
}

const (
	BlockStart = "# >>> sws drive >>>"
	BlockEnd   = "# <<< sws drive <<<"
)

// InstallSSHConfig puts the block at the top of the ssh config file (entries there come first,
// and a Match must precede any Host * that would set the same things), replacing one put there
// before.
func InstallSSHConfig(path, block string) error {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rest := string(old)
	if i := strings.Index(rest, BlockStart); i >= 0 {
		if j := strings.Index(rest[i:], BlockEnd); j >= 0 {
			end := i + j + len(BlockEnd)
			if end < len(rest) && rest[end] == '\n' {
				end++
			}
			rest = rest[:i] + rest[end:]
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFile(path, []byte(block+"\n"+strings.TrimLeft(rest, "\n")), 0o600)
}
