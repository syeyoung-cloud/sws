package drive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cyoung06/sws/internal/api"
)

type fixedToken string

func (f fixedToken) Token(context.Context, string) (string, error) { return string(f), nil }
func (fixedToken) Name() string                                    { return "fixed" }

// fakeDrive answers the drive's workload calls as the real one does, signing certificates with a
// CA of its own, for an hour, sent with a trailing newline (as the drive did before 0.0.28-3caa1db).
func fakeDrive(t *testing.T, now func() time.Time) (*httptest.Server, *int32) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caKey)
	var issued int32
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/sts/token":
			var in struct {
				Token, Owner string
				SSH          *struct{ PublicKey string }
				SMB          bool
			}
			json.NewDecoder(r.Body).Decode(&in)
			if in.Token != "wl" {
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
				return
			}
			if in.Owner != "alice" {
				w.WriteHeader(404)
				json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
				return
			}
			n := atomic.AddInt32(&issued, 1)
			name := "nworkload" + string(rune('a'+n))
			if in.SMB {
				json.NewEncoder(w).Encode(map[string]any{"user": name, "password": "pw", "validUntil": now().Add(time.Hour).Unix(), "share": "//smb.test/shared"})
				return
			}
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(in.SSH.PublicKey))
			if err != nil {
				w.WriteHeader(400)
				return
			}
			c := &ssh.Certificate{Key: pk, CertType: ssh.UserCert, KeyId: "job", ValidPrincipals: []string{name},
				ValidAfter: uint64(now().Unix()), ValidBefore: uint64(now().Add(time.Hour).Unix())}
			c.SignCert(rand.Reader, ca)
			json.NewEncoder(w).Encode(map[string]any{"user": name, "certificate": string(ssh.MarshalAuthorizedKey(c)),
				"validUntil": c.ValidBefore, "host": "drive.test", "port": 2022, "path": "/root/shared"})
		case r.Header.Get("Authorization") != "Bearer wl":
			w.WriteHeader(401)
		case r.Method == "POST" && r.URL.Path == "/api/v1/share-requests":
			json.NewEncoder(w).Encode(map[string]any{"id": "r1", "url": "https://drive.test/approve?id=r1", "expires": 0, "interval": 1})
		case r.Method == "GET" && r.URL.Path == "/api/v1/share-requests/r1":
			polls++
			state := "pending"
			if polls >= 2 {
				state = "approved"
			}
			json.NewEncoder(w).Encode(map[string]any{"state": state, "owner": "alice"})
		case r.Method == "DELETE" && r.URL.Path == "/api/v1/share-requests/r1":
			w.WriteHeader(204)
		case r.Method == "GET" && r.URL.Path == "/api/v1/workload/grants":
			json.NewEncoder(w).Encode(map[string]any{"grants": []map[string]any{{"id": 7, "name": "builds-7", "owner": "alice", "readOnly": true, "expires": nil}}})
		default:
			w.WriteHeader(404)
		}
	}))
	return srv, &issued
}

func TestRequestAndGrants(t *testing.T) {
	srv, _ := fakeDrive(t, time.Now)
	defer srv.Close()
	d := &Drive{URL: srv.URL, Identity: fixedToken("wl"), State: t.TempDir()}
	r, err := d.Ask(context.Background(), "builds", true)
	if err != nil || r.ID != "r1" || r.Interval != time.Second {
		t.Fatal(r, err)
	}
	dec, err := api.Wait(context.Background(), r, func(c context.Context) (api.Decision, error) { return d.Check(c, r.ID) }, nil)
	if err != nil || dec.Detail != "shared by alice" {
		t.Fatal(dec, err)
	}
	gs, err := d.Grants(context.Background())
	if err != nil || len(gs) != 1 || gs[0].Name != "builds-7" || !gs[0].ReadOnly {
		t.Fatal(gs, err)
	}
}

// A certificate is had once and kept while it has more than Renew left; near its end a new one is
// had for the same key. The kept certificate is one line, so ssh-keygen reads it.
func TestEnsureSSH(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	srv, issued := fakeDrive(t, clock)
	defer srv.Close()
	state := t.TempDir()
	d := &Drive{URL: srv.URL, Identity: fixedToken("wl"), State: state, Now: clock}
	s, err := d.EnsureSSH(context.Background(), "alice")
	if err != nil || !s.Renewed || s.Alias != "drive-alice" || s.Host != "drive.test" || s.Port != 2022 {
		t.Fatal(s, err)
	}
	dir := filepath.Join(state, "drive", "alice")
	cert, _ := os.ReadFile(filepath.Join(dir, "key-cert.pub"))
	if strings.Count(string(cert), "\n") != 1 {
		t.Fatalf("the certificate is not one line: %q", cert)
	}
	if out, err := exec.Command("ssh-keygen", "-L", "-f", filepath.Join(dir, "key-cert.pub")).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen refused the kept certificate: %v %s", err, out)
	}
	key1, _ := os.ReadFile(filepath.Join(dir, "key"))
	if fi, _ := os.Stat(filepath.Join(dir, "key")); fi.Mode().Perm() != 0o600 {
		t.Fatal("the key is readable by others")
	}

	again, err := d.EnsureSSH(context.Background(), "alice")
	if err != nil || again.Renewed || again.User != s.User || *issued != 1 {
		t.Fatalf("kept one was not used: %v %v issued %d", again, err, *issued)
	}
	now = now.Add(55 * time.Minute)
	renewed, err := d.EnsureSSH(context.Background(), "alice")
	if err != nil || !renewed.Renewed || renewed.User == s.User || *issued != 2 {
		t.Fatalf("not renewed near its end: %v %v", renewed, err)
	}
	key2, _ := os.ReadFile(filepath.Join(dir, "key"))
	if string(key1) != string(key2) {
		t.Fatal("the key changed")
	}
	conf, _ := os.ReadFile(filepath.Join(dir, "ssh_config"))
	if !strings.Contains(string(conf), "User "+renewed.User) {
		t.Fatalf("the entry names the old user: %s", conf)
	}

	if _, err := d.EnsureSSH(context.Background(), "bob"); err == nil || !strings.Contains(err.Error(), "shares nothing") {
		t.Fatal(err)
	}
	if _, err := d.EnsureSSH(context.Background(), "../x"); err == nil {
		t.Fatal("a name that is a path was taken")
	}
}

// ssh itself resolves drive-alice through the block: Match exec runs `sws drive ensure`, then the
// kept entry applies; a host that is not drive-* is left alone, and lines after the block apply to
// all hosts as before.
func TestSSHConfig(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no ssh")
	}
	state := t.TempDir()
	dir := filepath.Join(state, "drive", "alice")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "ssh_config"), []byte("Host drive-alice\n  HostName drive.test\n  Port 2022\n  User nabc\n  IdentitiesOnly yes\n"), 0o600)
	stub := filepath.Join(t.TempDir(), "sws")
	ran := filepath.Join(t.TempDir(), "ran")
	os.WriteFile(stub, []byte("#!/bin/sh\necho \"$@\" >> "+ran+"\n"), 0o755)

	cfg := filepath.Join(t.TempDir(), "config")
	os.WriteFile(cfg, []byte("ServerAliveInterval 7\nHost other\n  User someone\n"), 0o600)
	if err := InstallSSHConfig(cfg, SSHConfigBlock(stub, state)); err != nil {
		t.Fatal(err)
	}
	// installing again replaces the block, it does not add a second
	if err := InstallSSHConfig(cfg, SSHConfigBlock(stub, state)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfg)
	if strings.Count(string(b), BlockStart) != 1 || !strings.HasPrefix(string(b), BlockStart) {
		t.Fatalf("%s", b)
	}
	resolve := func(host string) map[string]string {
		out, err := exec.Command("ssh", "-F", cfg, "-G", host).CombinedOutput()
		if err != nil {
			t.Fatalf("ssh -G %s: %v %s", host, err, out)
		}
		m := map[string]string{}
		for _, l := range strings.Split(string(out), "\n") {
			if k, v, ok := strings.Cut(l, " "); ok {
				m[k] = v
			}
		}
		return m
	}
	a := resolve("drive-alice")
	if a["hostname"] != "drive.test" || a["port"] != "2022" || a["user"] != "nabc" || a["serveraliveinterval"] != "7" {
		t.Fatalf("drive-alice resolved to %v", a)
	}
	if r, _ := os.ReadFile(ran); strings.TrimSpace(string(r)) != "drive ensure drive-alice" {
		t.Fatalf("ensure ran as %q", r)
	}
	o := resolve("other")
	if o["user"] != "someone" || o["hostname"] != "other" || o["serveraliveinterval"] != "7" {
		t.Fatalf("other resolved to %v", o)
	}
}

func TestSMB(t *testing.T) {
	srv, _ := fakeDrive(t, time.Now)
	defer srv.Close()
	d := &Drive{URL: srv.URL, Identity: fixedToken("wl")}
	s, err := d.SMB(context.Background(), "alice")
	if err != nil || s.Password != "pw" || s.Share != "//smb.test/shared" {
		t.Fatal(s, err)
	}
}
