// Command sws gives a workload (a container, a CI job, a VM) its way into services that take
// workload identity, with no stored secret: it gets the workload's own OIDC token from the
// platform, asks members for access, and turns the token into what each service's normal tools
// use.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cyoung06/sws/internal/api"
	"github.com/cyoung06/sws/internal/config"
	"github.com/cyoung06/sws/internal/drive"
	"github.com/cyoung06/sws/internal/git"
	"github.com/cyoung06/sws/internal/identity"
	"github.com/cyoung06/sws/internal/pulp"

	// Roots to trust when the system has none (a bare image): used only then.
	_ "golang.org/x/crypto/x509roots/fallback"
)

// version is set at build time.
var version = "dev"

const usage = `sws: a workload's way into the drive, git and Pulp, with no stored secret.

  sws whoami                          who this workload is (issuer and subject) and the services set up
  sws token <audience>                print the workload's token for an audience

  sws drive request [-read-only] [label]
                                      ask a member to share a folder: prints a link, waits for the answer
  sws drive grants                    the folders shared with this workload
  sws drive setup                     let ssh, sftp and rsync reach drive-<owner> (once)
  sws drive ssh <owner>               get or renew the certificate for <owner>'s folders now
  sws drive smb <owner>               a password for the SMB share, acting for <owner>
  sws drive withdraw <id>             take a request back

  sws git setup                       make sws git's credential helper for the forge (once)
  sws git request <owner> [-repo r]... [-permission read|write|admin] [-create] [label]
                                      ask a member for rights on an org or account
  sws git token <owner>/<repo>        print a token for one repo (for a Forgejo CLI)
  sws git whoami                      this workload's agent on the forge
  sws git create-repo <owner>/<name> [-public]
  sws git withdraw <id>

  sws pulp request <base path>:pull|push... [-label text]
                                      ask a member for pull or push on distributions
  sws pulp token                      print the token (Bearer, or Basic with user __token__)
  sws pulp withdraw <id>

Configuration: ` + "`sws whoami`" + ` says which file was read; see the README.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		var u usageError
		if errors.As(err, &u) {
			fmt.Fprint(os.Stderr, usage)
			fmt.Fprintln(os.Stderr, "\nsws:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "sws:", err)
		os.Exit(1)
	}
}

type usageError string

func (u usageError) Error() string { return string(u) }

// parse reads flags anywhere among the arguments and returns the rest.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usageError(fs.Name() + ": " + err.Error())
		}
		args = fs.Args()
		if len(args) == 0 {
			return rest, nil
		}
		rest = append(rest, args[0])
		args = args[1:]
	}
}

type env struct {
	cfg   *config.Config
	id    identity.Source
	state string
	out   io.Writer
	err   io.Writer
}

func stateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "sws")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "state", "sws")
	}
	return filepath.Join(os.TempDir(), "sws-"+fmt.Sprint(os.Getuid()))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("no command")
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return nil
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "sws", version)
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	id, idErr := identity.New(cfg.Identity.Source, cfg.Identity.Command)
	e := &env{cfg: cfg, id: id, state: stateDir(), out: stdout, err: stderr}
	needID := func() error { return idErr }
	switch args[0] {
	case "whoami":
		return e.whoami(ctx, idErr)
	case "token":
		if len(args) != 2 {
			return usageError("token <audience>")
		}
		if err := needID(); err != nil {
			return err
		}
		t, err := id.Token(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, t)
		return nil
	case "drive":
		if cfg.Drive == nil {
			return notSetUp("drive", cfg)
		}
		if err := needID(); err != nil {
			return err
		}
		return e.drive(ctx, args[1:])
	case "git":
		if cfg.Git == nil {
			return notSetUp("git", cfg)
		}
		if len(args) > 1 && args[1] == "credential" {
			// git calls this; it must never fail loudly for hosts that aren't ours
			if len(args) < 3 || args[2] != "get" {
				return nil
			}
			if idErr != nil {
				fmt.Fprintln(stderr, "sws:", idErr)
				return nil
			}
			return e.git().Credential(ctx, stdin, stdout, stderr)
		}
		if err := needID(); err != nil {
			return err
		}
		return e.gitCmd(ctx, args[1:])
	case "pulp":
		if cfg.Pulp == nil {
			return notSetUp("pulp", cfg)
		}
		if err := needID(); err != nil {
			return err
		}
		return e.pulpCmd(ctx, args[1:])
	}
	return usageError("unknown command " + args[0])
}

func notSetUp(service string, cfg *config.Config) error {
	where := "no configuration file was found (" + strings.Join(config.Paths(), ", ") + ")"
	if cfg.Path != "" {
		where = cfg.Path + " has no [" + service + "] section"
	}
	return fmt.Errorf("%s is not set up: %s", service, where)
}

func (e *env) whoami(ctx context.Context, idErr error) error {
	if e.cfg.Path != "" {
		fmt.Fprintln(e.out, "configuration:", e.cfg.Path)
	} else {
		fmt.Fprintln(e.out, "configuration: none ("+strings.Join(config.Paths(), ", ")+")")
	}
	var services []string
	audience := ""
	if d := e.cfg.Drive; d != nil {
		services, audience = append(services, "drive "+d.URL), d.Audience
	}
	if g := e.cfg.Git; g != nil {
		services = append(services, "git "+g.Host+" (git-sts "+g.STS+")")
		if audience == "" {
			audience = g.Audience
		}
	}
	if p := e.cfg.Pulp; p != nil {
		services = append(services, "pulp "+p.URL)
		if audience == "" {
			audience = p.Audience
		}
	}
	if len(services) == 0 {
		services = []string{"none"}
	}
	fmt.Fprintln(e.out, "services:", strings.Join(services, ", "))
	if idErr != nil {
		return idErr
	}
	fmt.Fprintln(e.out, "identity source:", e.id.Name())
	if audience == "" {
		return nil
	}
	t, err := e.id.Token(ctx, audience)
	if err != nil {
		return err
	}
	c, err := identity.Peek(t)
	if err != nil {
		return err
	}
	fmt.Fprintln(e.out, "issuer: ", c.Issuer)
	fmt.Fprintln(e.out, "subject:", c.Subject)
	return nil
}

// wait prints the link and waits for the member's answer.
func (e *env) wait(ctx context.Context, r api.Request, check func(context.Context) (api.Decision, error), withdraw func(context.Context) error) error {
	fmt.Fprintf(e.out, "Send this link to a member, who opens it signed in and answers:\n\n  %s\n\nWaiting for the answer (request %s; Ctrl-C withdraws it)...\n", r.URL, r.ID)
	d, err := api.Wait(ctx, r, check, withdraw)
	if err != nil {
		return err
	}
	fmt.Fprintln(e.out, "Approved:", d.Detail)
	return nil
}

func self() string {
	p, err := os.Executable()
	if err != nil {
		return "sws"
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func (e *env) driveClient() *drive.Drive {
	return &drive.Drive{URL: e.cfg.Drive.URL, Audience: e.cfg.Drive.Audience, Identity: e.id, State: e.state}
}

func (e *env) drive(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("drive: which command?")
	}
	d := e.driveClient()
	switch args[0] {
	case "request":
		fs := flag.NewFlagSet("drive request", flag.ContinueOnError)
		ro := fs.Bool("read-only", false, "ask to read only")
		rest, err := parse(fs, args[1:])
		if err != nil {
			return err
		}
		r, err := d.Ask(ctx, strings.Join(rest, " "), *ro)
		if err != nil {
			return err
		}
		return e.wait(ctx, r, func(c context.Context) (api.Decision, error) { return d.Check(c, r.ID) }, func(c context.Context) error { return d.Withdraw(c, r.ID) })
	case "withdraw":
		if len(args) != 2 {
			return usageError("drive withdraw <id>")
		}
		return d.Withdraw(ctx, args[1])
	case "grants":
		gs, err := d.Grants(ctx)
		if err != nil {
			return err
		}
		if len(gs) == 0 {
			fmt.Fprintln(e.out, "Nothing is shared with this workload. Ask with `sws drive request`.")
			return nil
		}
		for _, g := range gs {
			access := "read and write"
			if g.ReadOnly {
				access = "read only"
			}
			until := ""
			if g.Expires != nil {
				until = ", until " + time.Unix(*g.Expires, 0).Format(time.DateTime)
			}
			fmt.Fprintf(e.out, "%-24s from %-16s %s%s   (ssh: %s:/root/shared/%s)\n", g.Name, g.Owner, access, until, drive.Alias(g.Owner), g.Name)
		}
		return nil
	case "setup":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path := filepath.Join(home, ".ssh", "config")
		if err := drive.InstallSSHConfig(path, drive.SSHConfigBlock(self(), e.state)); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s: ssh, sftp and rsync now reach drive-<owner>, renewing the certificate as needed.\n", path)
		return nil
	case "ssh":
		if len(args) != 2 {
			return usageError("drive ssh <owner>")
		}
		s, err := d.EnsureSSH(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s: user %s at %s:%d, folders in %s, good until %s\n", s.Alias, s.User, s.Host, s.Port, s.Path, s.ValidUntil.Format(time.DateTime))
		fmt.Fprintf(e.out, "  sftp %s    rsync -a ./out/ %s:%s/<folder>/\n", s.Alias, s.Alias, s.Path)
		return nil
	case "ensure":
		// ssh's Match exec: true (exit 0) lets the entries apply. Says nothing on success.
		if len(args) != 2 {
			return usageError("drive ensure <alias>")
		}
		owner, ok := drive.OwnerOfAlias(args[1])
		if !ok {
			return fmt.Errorf("%q is not a drive-<owner> alias", args[1])
		}
		_, err := d.EnsureSSH(ctx, owner)
		return err
	case "smb":
		if len(args) != 2 {
			return usageError("drive smb <owner>")
		}
		s, err := d.SMB(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(e.out, "share:    %s\nuser:     %s\npassword: %s\nstarts sessions until %s\n", s.Share, s.User, s.Password, time.Unix(s.ValidUntil, 0).Format(time.DateTime))
		return nil
	}
	return usageError("drive: unknown command " + args[0])
}

func (e *env) git() *git.Git {
	return &git.Git{STS: e.cfg.Git.STS, Audience: e.cfg.Git.Audience, Host: e.cfg.Git.Host, Identity: e.id}
}

func (e *env) gitCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("git: which command?")
	}
	g := e.git()
	switch args[0] {
	case "setup":
		if err := g.Setup(self() + " git credential"); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "git uses sws for https://%s\n", g.Host)
		return nil
	case "token":
		if len(args) != 2 || !strings.Contains(args[1], "/") {
			return usageError("git token <owner>/<repo>")
		}
		t, err := g.Token(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintln(e.out, t.Token)
		return nil
	case "whoami":
		w, err := g.Whoami(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s (%s, %s)\n", w.Agent, w.Subject, w.Issuer)
		return nil
	case "create-repo":
		fs := flag.NewFlagSet("git create-repo", flag.ContinueOnError)
		public := fs.Bool("public", false, "make it public")
		rest, err := parse(fs, args[1:])
		if err != nil {
			return err
		}
		owner, name, ok := strings.Cut(strings.Join(rest, ""), "/")
		if len(rest) != 1 || !ok || owner == "" || name == "" {
			return usageError("git create-repo <owner>/<name> [-public]")
		}
		u, err := g.CreateRepo(ctx, owner, name, !*public)
		if err != nil {
			return err
		}
		fmt.Fprintln(e.out, u)
		return nil
	case "request":
		fs := flag.NewFlagSet("git request", flag.ContinueOnError)
		var repos multi
		fs.Var(&repos, "repo", "a repo of the owner's (again for more); none: every repo of an org")
		perm := fs.String("permission", "write", "read, write or admin")
		create := fs.Bool("create", false, "also ask to make repos there")
		rest, err := parse(fs, args[1:])
		if err != nil {
			return err
		}
		if len(rest) < 1 {
			return usageError("git request <owner> [-repo r]... [-permission read|write|admin] [-create] [label]")
		}
		r, err := g.Ask(ctx, rest[0], repos, *perm, *create, strings.Join(rest[1:], " "))
		if err != nil {
			return err
		}
		return e.wait(ctx, r, func(c context.Context) (api.Decision, error) { return g.Check(c, r.ID) }, func(c context.Context) error { return g.Withdraw(c, r.ID) })
	case "withdraw":
		if len(args) != 2 {
			return usageError("git withdraw <id>")
		}
		return g.Withdraw(ctx, args[1])
	}
	return usageError("git: unknown command " + args[0])
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func (e *env) pulpCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("pulp: which command?")
	}
	p := &pulp.Pulp{URL: e.cfg.Pulp.URL, Audience: e.cfg.Pulp.Audience, Identity: e.id}
	switch args[0] {
	case "token":
		t, err := p.Token(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(e.out, t)
		return nil
	case "request":
		fs := flag.NewFlagSet("pulp request", flag.ContinueOnError)
		label := fs.String("label", "", "what it is for, shown to the member")
		rest, err := parse(fs, args[1:])
		if err != nil {
			return err
		}
		if len(rest) == 0 {
			return usageError("pulp request <base path>:pull|push... [-label text]")
		}
		var asks []pulp.Ask
		for _, s := range rest {
			a, err := pulp.ParseAsk(s)
			if err != nil {
				return usageError(err.Error())
			}
			asks = append(asks, a)
		}
		r, err := p.Ask(ctx, *label, asks)
		if err != nil {
			return err
		}
		return e.wait(ctx, r, func(c context.Context) (api.Decision, error) { return p.Check(c, r.ID) }, func(c context.Context) error { return p.Withdraw(c, r.ID) })
	case "withdraw":
		if len(args) != 2 {
			return usageError("pulp withdraw <id>")
		}
		return p.Withdraw(ctx, args[1])
	}
	return usageError("pulp: unknown command " + args[0])
}
