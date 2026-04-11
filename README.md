# sesh

Named persistent shell sessions — zero config, single binary.

`sesh` lets you create, detach from, and reattach to shell sessions, similar to `tmux` or `screen`, but with a simpler interface and no configuration. It's a single static binary with no dependencies.

## Install

```bash
npm install -g sesh-cli
```

Or build from source:

```bash
cargo install --path .
```

## Quick start

```bash
sesh dev .              # Create a session named "dev" in the current directory
                        # Press Ctrl-\ to detach
sesh dev                # Reattach (searches local, then remotes)
sesh                    # List all sessions
sesh kill dev           # Kill a session
```

## Features

- **Named sessions** — create and attach by name
- **Persistent** — sessions survive disconnects; reattach anytime
- **Smart lookup** — `sesh <name>` finds sessions across local and remote hosts
- **Scrollback replay** — see recent terminal history when reattaching
- **Tab completion** — auto-configured for bash and zsh
- **Remote support** — manage sessions on remote hosts over SSH
- **Cross-platform deploy** — `sesh deploy @host` installs the correct binary
- **Export/import** — back up and recreate your session layout
- **No screen clearing** — does not interfere with terminal state

## Usage

```
sesh                       List all sessions (local + remotes)
sesh <name> [dir]          Create or attach to a session
sesh kill <name>           Kill a session (local or remote)

sesh @<host>               List sessions on a remote host
sesh @<host> <name> [dir]  Create or attach to a remote session
sesh @<host> kill <name>   Kill a remote session

sesh deploy @<host>        Deploy sesh to a remote host
sesh upgrade               Redeploy sesh to all known remotes
sesh export                Export session layout
sesh import [file]         Recreate sessions from an export
sesh completions <shell>   Print shell completions (bash, zsh)
sesh help                  Show help
```

**Detach** from a session with `Ctrl-\`.

## Smart session lookup

When you run `sesh <name>` without specifying a host:

1. **Local first** — attaches if a local session matches
2. **Remote search** — queries all known remotes in parallel
3. **Auto-connect** — connects if found on exactly one remote
4. **Prompt** — asks you to choose if found on multiple remotes

`sesh kill` uses the same smart lookup.

## Remote sessions

```bash
sesh @myserver dev ~/project    # Create a session on a remote host
sesh deploy @myserver           # Deploy sesh to a remote host
sesh upgrade                    # Redeploy to all known remotes
```

Deploy detects the remote OS/arch and installs via npm. Falls back to copying the local binary if platforms match.

## How it works

sesh is a single Rust binary that manages PTY-backed shell sessions via Unix sockets. Each session is a background daemon process that owns a PTY and listens on `~/.sesh/<name>.sock`. The daemon maintains a scrollback buffer so reattaching shows recent terminal history. The client handles SSH disconnections gracefully — sessions survive any network interruption.

## Supported platforms

| OS | Architecture |
|---|---|
| Linux | x86_64 |
| Linux | aarch64 |
| macOS | Apple Silicon (M1+) |
| macOS | Intel |

Linux binaries are statically linked (musl) and work on any distro.

## License

MIT
