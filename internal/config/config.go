// Package config reads sws's configuration: where each service is and the audience its tokens
// are made out to. Nothing about any one deployment is in the code; the file says it all.
//
// The file is $SWS_CONFIG if set, else the first that exists of
// $XDG_CONFIG_HOME/sws/config.toml (~/.config/sws/config.toml) and /etc/sws/config.toml:
//
//	[identity]
//	source = "auto"          # auto, kubernetes, github or command
//	command = ""             # for "command": prints a token for the audience in $SWS_AUDIENCE
//
//	[drive]
//	url = "https://files.drive.example"
//	audience = "https://files.drive.example"
//
//	[git]
//	sts = "https://sts.git.example/sts"
//	audience = "https://sts.git.example"
//	host = "git.example"
//
//	[pulp]
//	url = "https://pulp.example"
//	audience = "https://pulp.example"
//
// A service without its section is not set up, and its commands say so.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Identity struct {
	Source  string `toml:"source"`
	Command string `toml:"command"`
}

type Drive struct {
	URL      string `toml:"url"`
	Audience string `toml:"audience"`
}

type Git struct {
	STS      string `toml:"sts"`
	Audience string `toml:"audience"`
	Host     string `toml:"host"`
}

type Pulp struct {
	URL      string `toml:"url"`
	Audience string `toml:"audience"`
}

type Config struct {
	Identity Identity `toml:"identity"`
	Drive    *Drive   `toml:"drive"`
	Git      *Git     `toml:"git"`
	Pulp     *Pulp    `toml:"pulp"`
	// Path is the file it was read from ("" when there was none).
	Path string `toml:"-"`
}

// Paths are where the file is looked for, in order.
func Paths() []string {
	if p := os.Getenv("SWS_CONFIG"); p != "" {
		return []string{p}
	}
	var out []string
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		out = append(out, filepath.Join(d, "sws", "config.toml"))
	} else if h, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(h, ".config", "sws", "config.toml"))
	}
	return append(out, "/etc/sws/config.toml")
}

// Load reads the first file of Paths that exists. No file is no services, not an error, except
// that $SWS_CONFIG, when set, must exist.
func Load() (*Config, error) {
	explicit := os.Getenv("SWS_CONFIG") != ""
	for _, p := range Paths() {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) && !explicit {
			continue
		}
		return Read(p)
	}
	return &Config{Identity: Identity{Source: "auto"}}, nil
}

// Read reads one file.
func Read(path string) (*Config, error) {
	c := &Config{}
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		return nil, fmt.Errorf("%s: unknown setting %s", path, un[0])
	}
	c.Path = path
	if c.Identity.Source == "" {
		c.Identity.Source = "auto"
	}
	switch c.Identity.Source {
	case "auto", "kubernetes", "github":
	case "command":
		if c.Identity.Command == "" {
			return nil, fmt.Errorf("%s: identity source \"command\" needs a command", path)
		}
	default:
		return nil, fmt.Errorf("%s: unknown identity source %q", path, c.Identity.Source)
	}
	check := func(section, name, v string, url bool) error {
		if v == "" {
			return fmt.Errorf("%s: [%s] needs %s", path, section, name)
		}
		if url && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") {
			return fmt.Errorf("%s: [%s] %s is not a URL: %q", path, section, name, v)
		}
		return nil
	}
	var errs []error
	if d := c.Drive; d != nil {
		d.URL = strings.TrimRight(d.URL, "/")
		errs = append(errs, check("drive", "url", d.URL, true), check("drive", "audience", d.Audience, false))
	}
	if g := c.Git; g != nil {
		g.STS = strings.TrimRight(g.STS, "/")
		errs = append(errs, check("git", "sts", g.STS, true), check("git", "audience", g.Audience, false), check("git", "host", g.Host, false))
	}
	if p := c.Pulp; p != nil {
		p.URL = strings.TrimRight(p.URL, "/")
		errs = append(errs, check("pulp", "url", p.URL, true), check("pulp", "audience", p.Audience, false))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}
