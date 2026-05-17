# sesh

Named persistent shell sessions — zero config, single binary.

`sesh` lets you create, detach from, and reattach to shell sessions, similar to `tmux` or `screen`, but with a simpler interface and no configuration. It's a single static binary with no dependencies.

## Install

```bash
curl -fsSL "https://github.com/BobStrogg/sesh/releases/latest/download/sesh-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/arm64/aarch64/')" -o ~/.local/bin/sesh && chmod +x ~/.local/bin/sesh
```

Or via npm:

```bash
npm install -g @bobstrogg/sesh
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
sesh --kill dev         # Kill a session
```

## Features

- **Named sessions** — create and attach by name
- **Persistent** — sessions survive disconnects; reattach anytime
- **Smart lookup** — `sesh <name>` finds sessions across local and remote hosts
- **Scrollback replay** — see recent terminal history when reattaching
- **Tab completion** — auto-configured for bash and zsh
- **Remote support** — manage sessions on remote hosts over SSH
- **Cross-platform deploy** — `sesh --deploy @host` installs the correct binary
- **One-shot exec** — `sesh --exec <name> -- <cmd>` wraps a command in a watchable session and propagates its exit code
- **File sync** — list paths in `~/.config/sesh/sync` and they're rsynced to every remote on connect
- **Structured event log** — `SESH_EVENT_LOG=<path>` for machine-readable sync/deploy events (JSONL)
- **Export/import** — back up and recreate your session layout
- **No screen clearing** — does not interfere with terminal state

## Usage

```
sesh                          List all sessions (local + remotes)
sesh <name> [dir]             Create or attach to a session
sesh --kill <name>            Kill a session (local or remote)
sesh --exec <name> [opts] -- <cmd> [args...]
                              Run <cmd> in a fresh session, exit with
                              <cmd>'s return code. Attach with
                              `sesh <name>` while running to watch.
                              Options: --print --keep -C <dir>

sesh @<host>                  List sessions on a remote host
sesh @<host> <name> [dir]     Create or attach to a remote session
sesh @<host> --kill <name>    Kill a remote session
sesh @<host> --exec <name> [opts] -- <cmd> [args...]
                              Same as --exec, but on a remote host.

sesh --deploy @<host>         Deploy sesh to a remote host
sesh --upgrade                Redeploy sesh to all known remotes
sesh --export                 Export session layout
sesh --import [file]          Recreate sessions from an export
sesh --completions <shell>    Print shell completions (bash, zsh)
sesh --help                   Show help (-h)
sesh --version                Print version (-V)
```

**Detach** from a session with `Ctrl-\`.

## Smart session lookup

When you run `sesh <name>` without specifying a host:

1. **Local first** — attaches if a local session matches
2. **Remote search** — queries all known remotes in parallel
3. **Auto-connect** — connects if found on exactly one remote
4. **Prompt** — asks you to choose if found on multiple remotes

`sesh --kill` uses the same smart lookup.

## Remote sessions

```bash
sesh @myserver dev ~/project    # Create a session on a remote host
sesh --deploy @myserver         # Deploy sesh to a remote host
sesh --upgrade                  # Redeploy to all known remotes
```

Deploy detects the remote OS/arch and installs via npm. Falls back to copying the local binary if platforms match.

## One-shot exec (`sesh --exec`)

Wrap a single command in a fresh sesh session and propagate its exit code as sesh's own:

```bash
sesh --exec build -- cargo build --release   # exits with cargo's status
echo $?                                       # 0 if cargo succeeded, non-zero otherwise
```

The session is **attachable while the command is running** — from anywhere:

```bash
sesh build                # watch it locally
sesh @worker build        # watch it on a remote
```

Useful for long-running jobs you want to monitor without keeping a terminal pinned. On exit the session auto-cleans up.

Options:

- `--print` — also dump the command's captured output (last ~256 KB) to stdout after it finishes
- `-C <dir>` — `cd` to *dir* before running the command
- `--keep` — leave the session alive after the command exits (sketched; not yet implemented)

For remotes, `sesh @<host> --exec ...` runs the same flow over SSH; argv is POSIX-quoted on the way over.

## File sync

Anything you list in `~/.config/sesh/sync` is rsync'd to every remote
host you connect to.  Lines that start with `#` are ignored.  Paths
must be `$HOME`-relative — they're mirrored to the same path under
`$HOME` on the remote.

```text
# ~/.config/sesh/sync
.config/devin/skills
.config/devin/hooks.v1.json
bin/my-script
```

The push is gated by a content fingerprint stored under
`~/.local/state/sesh/remotes/<host>.synced` — re-attaching to the same
remote without changing any of the listed files is a no-op.  Set
`SESH_NO_SYNC=1` to disable the feature for one invocation.

`rsync` is used when available (incremental, `--delete` so removed
files are removed remotely).  When `rsync` isn't on the local
machine, sesh falls back to `scp -r` (no delete semantics — files
removed locally stay on the remote).

## Structured event log

Set `SESH_EVENT_LOG=<path>` to have sesh append JSON-Lines records of
significant sync / deploy events to that file instead of printing
"Syncing files …" / "failed to push …" to stderr.  Tools that embed
sesh (editor wrappers, CI runners, anything that wants to render its
own UI) use this to show toasts/notifications without parsing
human-readable output.

```text
{"ts":"2026-05-12T03:45:01Z","event":"sync_start","host":"prod"}
{"ts":"2026-05-12T03:45:01Z","event":"sync_path_pushed","path":".config/devin/skills","bytes":4096}
{"ts":"2026-05-12T03:45:01Z","event":"sync_path_failed","path":"bin/foo","exit_code":12,"stderr":"..."}
{"ts":"2026-05-12T03:45:01Z","event":"tool_missing","tool":"rsync","path":"bin/foo"}
{"ts":"2026-05-12T03:45:01Z","event":"sync_done","ok":false}
{"ts":"2026-05-12T03:45:01Z","event":"deploy_failed","host":"prod","step":"detect_platform","stderr":"..."}
```

The log file is opened `O_APPEND`, so concurrent sesh invocations can
share a single log.  When the env var is unset, behaviour is unchanged.

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
