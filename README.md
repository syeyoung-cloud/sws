# sws

A workload's way into services that take workload identity, with no stored secret. A workload is
a program that is not a person: a container, a CI job, a VM. sws gets the workload's own OIDC
token from the platform it runs on, asks a person for access when it has none, and turns the token
into what each service's ordinary tools use.

| Service | What sws does | Then use |
|---|---|---|
| a drive with a workload STS | SSH certificate (renewed when ssh connects) or SMB password | `sftp`, `rsync`, `sshfs`, `smbclient` |
| Forgejo behind [git-sts](https://github.com/cyoung06/git-sts) | git's credential helper; a token for one repo | `git`, a Forgejo CLI |
| Pulp with workload identity | the token itself (Bearer, or Basic with user `__token__`) | `pulp`, `pip`, `twine`, `npm` |

Every service follows the same seam: the service verifies the token, a person grants the token's
issuer and subject, and the workload asks for access with a request a person approves by a link.
sws never decides anything itself; the services do.

## Identity

sws asks for a fresh token for each service's audience:

- **Kubernetes:** the pod's service account token must be allowed to create tokens for its own
  account (`create` on `serviceaccounts/token` for that one account). sws asks the API server
  (`TokenRequest`) for a token bound to the pod, for an hour.
- **GitHub Actions:** the job needs `permissions: id-token: write`.
- **Anything else:** a command that prints a token for the audience in `$SWS_AUDIENCE`.

`sws whoami` shows the issuer and subject a person grants to.

## Configuration

`$SWS_CONFIG`, else `~/.config/sws/config.toml`, else `/etc/sws/config.toml`. A service without
its section is not set up.

```toml
[identity]
source = "auto"            # auto, kubernetes, github or command
# command = "my-agent token"   # for "command": print a token for $SWS_AUDIENCE

[drive]
url = "https://files.drive.example"
audience = "https://files.drive.example"

[git]
sts = "https://sts.git.example/sts"
audience = "https://sts.git.example"
host = "git.example"

[pulp]
url = "https://pulp.example"
audience = "https://pulp.example"
```

## Use

```sh
sws whoami

# the drive
sws drive request -read-only "nightly build output"   # prints a link for a person; waits
sws drive grants                                      # what is shared, and from whom
sws drive setup                                       # once: ssh reaches drive-<owner>
rsync -a ./out/ drive-alice:/root/shared/builds-17/
sftp drive-alice
sws drive smb alice                                   # SMB instead

# git
sws git setup                                         # once
sws git request alice -repo app -permission write "CI pushes tags"
git clone https://git.example/alice/app
sws git token alice/app                               # for a Forgejo CLI's token command

# Pulp
sws pulp request pypi/club:push -label "release job"
TWINE_USERNAME=__token__ TWINE_PASSWORD=$(sws pulp token) twine upload --repository-url https://pulp.example/pypi/club/legacy/ dist/*
```

A request waits for the answer, asking every few seconds as the service says; Ctrl-C withdraws it.

### The drive over SSH

`sws drive setup` puts a block at the top of `~/.ssh/config`:

```
Match host "drive-*" exec "/usr/local/bin/sws drive ensure %n"
  Include ~/.local/state/sws/drive/*/ssh_config
Match all
```

Before ssh connects to `drive-alice`, it runs `sws drive ensure`. That gets a certificate acting for
alice the first time, and a new one when the kept one has less than ten minutes left. The key is
made once and kept in `~/.local/state/sws/drive/alice/`; the drive signs only its public half. Pin
the drive's host key in `known_hosts`; sws does not accept host keys for you.

## Building

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags)" -o sws ./cmd/sws
go test ./...
```

Releases are built by `.github/workflows/release.yml` on `v*` tags.

## License

MIT
