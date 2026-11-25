package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRead(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "c.toml")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	c, err := Read(write(`
[drive]
url = "https://files.drive.test/"
audience = "https://files.drive.test"
[git]
sts = "https://sts.git.test/sts"
audience = "https://sts.git.test"
host = "git.test"
`))
	if err != nil || c.Drive.URL != "https://files.drive.test" || c.Git.Host != "git.test" || c.Pulp != nil || c.Identity.Source != "auto" {
		t.Fatal(c, err)
	}
	for bad, want := range map[string]string{
		"[drive]\nurl = \"x\"\naudience = \"a\"\n":       "not a URL",
		"[drive]\nurl = \"https://x\"\n":                 "needs audience",
		"[pulp]\nurl = \"https://x\"\naudence = \"a\"\n": "unknown setting",
		"[identity]\nsource = \"command\"\n":             "needs a command",
		"[identity]\nsource = \"aws\"\n":                 "unknown identity source",
	} {
		if _, err := Read(write(bad)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	t.Setenv("SWS_CONFIG", filepath.Join(dir, "missing.toml"))
	if _, err := Load(); err == nil {
		t.Error("a named file that is missing was taken as none")
	}
}
