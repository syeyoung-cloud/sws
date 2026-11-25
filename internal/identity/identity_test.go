package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

// The pod's own token asks the API server, over its CA, for a token of its own account made out to
// the audience, bound to the pod; when the host's name is no pod's, unbound.
func TestKubernetes(t *testing.T) {
	own := jwt(map[string]any{"iss": "https://k8s.test", "sub": "system:serviceaccount:containers:identity-x"})
	var asked []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/containers/serviceaccounts/identity-x/token" || r.Header.Get("Authorization") != "Bearer "+own {
			http.Error(w, "no", 403)
			return
		}
		var body struct {
			Spec map[string]any `json:"spec"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		asked = append(asked, body.Spec)
		if ref, ok := body.Spec["boundObjectRef"].(map[string]any); ok && ref["name"] != "pod-1" {
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(map[string]string{"message": "pods not found"})
			return
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": map[string]string{"token": "minted"}})
	}))
	defer srv.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "token"), []byte(own+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)

	k := &Kubernetes{Dir: dir, API: srv.URL, Pod: "pod-1"}
	tok, err := k.Token(context.Background(), "https://files.test")
	if err != nil || tok != "minted" {
		t.Fatalf("%q %v", tok, err)
	}
	if a := asked[0]; a["audiences"].([]any)[0] != "https://files.test" || a["expirationSeconds"].(float64) != 3600 || a["boundObjectRef"] == nil {
		t.Fatalf("asked %v", a)
	}
	asked = nil
	k.Pod = "not-a-pod"
	if tok, err := k.Token(context.Background(), "a"); err != nil || tok != "minted" || len(asked) != 2 || asked[1]["boundObjectRef"] != nil {
		t.Fatalf("unbound after 404: %q %v %v", tok, err, asked)
	}
	// a token that is not a service account's
	os.WriteFile(filepath.Join(dir, "token"), []byte(jwt(map[string]any{"sub": "alice"})), 0o600)
	if _, err := k.Token(context.Background(), "a"); err == nil || !strings.Contains(err.Error(), "not a service account") {
		t.Fatal(err)
	}
}

func TestKubernetesRefused(t *testing.T) {
	own := jwt(map[string]any{"sub": "system:serviceaccount:ns:sa"})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]string{"message": "forbidden"})
	}))
	defer srv.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "token"), []byte(own), 0o600)
	os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	_, err := (&Kubernetes{Dir: dir, API: srv.URL, Pod: "-"}).Token(context.Background(), "a")
	if err == nil || !strings.Contains(err.Error(), "may not create its own tokens") {
		t.Fatal(err)
	}
}

func TestGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer req-token" || r.URL.Query().Get("audience") != "https://sts.git.test" || r.URL.Query().Get("api-version") != "2.0" {
			http.Error(w, "no", 401)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"value": "gh-jwt"})
	}))
	defer srv.Close()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/token?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-token")
	s, err := New("auto", "", "")
	if err != nil || s.Name() != "github" {
		t.Fatal(s, err)
	}
	if tok, err := s.Token(context.Background(), "https://sts.git.test"); err != nil || tok != "gh-jwt" {
		t.Fatalf("%q %v", tok, err)
	}
}

func TestCommand(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	KubeDir = t.TempDir()
	s, err := New("auto", `printf 'tok-for-%s\n' "$SWS_AUDIENCE"`, "")
	if err != nil || s.Name() != "command" {
		t.Fatal(s, err)
	}
	if tok, err := s.Token(context.Background(), "https://pulp.test"); err != nil || tok != "tok-for-https://pulp.test" {
		t.Fatalf("%q %v", tok, err)
	}
	if _, err := New("auto", "", "http://127.0.0.1:1"); err == nil {
		t.Fatal("no source anywhere was taken")
	}
}

// A VM's metadata service: one audience, the Metadata header, never through a proxy; auto finds it
// when nothing else is there.
func TestMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/token" || r.Header.Get("Metadata") != "true" || r.URL.Query().Get("audience") != "https://pulp.test" {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"token": "vm-jwt", "expiresIn": 3599, "issuer": "https://k8s.test", "subject": "system:serviceaccount:cloud:identity-x"})
	}))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	KubeDir = t.TempDir()
	s, err := New("auto", "", srv.URL)
	if err != nil || s.Name() != "metadata" {
		t.Fatal(s, err)
	}
	if tok, err := s.Token(context.Background(), "https://pulp.test"); err != nil || tok != "vm-jwt" {
		t.Fatalf("%q %v", tok, err)
	}
	if _, err := s.Token(context.Background(), "https://other.test"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
}
