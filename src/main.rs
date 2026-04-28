use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use nix::libc;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::termios::{self, SetArg, Termios};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{self, ForkResult, Pid};

// Portable ioctl request type (c_ulong on macOS/glibc, c_int on musl)
#[cfg(target_os = "macos")]
type IoctlReq = libc::c_ulong;
#[cfg(all(target_os = "linux", target_env = "musl"))]
type IoctlReq = libc::c_int;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
type IoctlReq = libc::c_ulong;

// ── Protocol ──────────────────────────────────────────────────────────────
// Client -> Master: [type:u8][len_hi:u8][len_lo:u8][payload...]
//   MSG_INPUT: keyboard data
//   MSG_WINCH: [rows_hi][rows_lo][cols_hi][cols_lo]  (len=4)
// Master -> Client: raw PTY output (no framing)

const MSG_INPUT: u8 = 0;
const MSG_WINCH: u8 = 1;
const DETACH_KEY: u8 = 0x1c; // Ctrl-backslash
const BUF_SIZE: usize = 8192;

fn send_input(stream: &mut UnixStream, buf: &[u8]) -> io::Result<()> {
    let len = buf.len().min(BUF_SIZE) as u16;
    let hdr = [MSG_INPUT, (len >> 8) as u8, len as u8];
    stream.write_all(&hdr)?;
    stream.write_all(&buf[..len as usize])
}

fn send_winch(stream: &mut UnixStream, rows: u16, cols: u16) -> io::Result<()> {
    let msg = [
        MSG_WINCH, 0, 4,
        (rows >> 8) as u8, rows as u8,
        (cols >> 8) as u8, cols as u8,
    ];
    stream.write_all(&msg)
}

// ── Paths ─────────────────────────────────────────────────────────────────
fn sesh_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| "/tmp".into())).join(".sesh")
}
fn sock_path(name: &str) -> PathBuf { sesh_dir().join(format!("{name}.sock")) }
fn meta_path(name: &str) -> PathBuf { sesh_dir().join(format!("{name}.dir")) }
fn pid_path(name: &str) -> PathBuf { sesh_dir().join(format!("{name}.pid")) }
fn remotes_dir() -> PathBuf { sesh_dir().join("remotes") }
fn remote_cache_path(host: &str) -> PathBuf { remotes_dir().join(format!("{host}.sessions")) }

// Local sesh version, embedded at compile time from Cargo.toml.
const VERSION: &str = env!("CARGO_PKG_VERSION");

// Marker file written when this version of sesh has deployed itself to a
// remote. Embedding the version in the filename means a new local sesh
// release auto-invalidates older markers and triggers a redeploy on the
// next `sesh @<host>` — without the user having to run `sesh upgrade`.
fn remote_marker_path(host: &str) -> PathBuf {
    remotes_dir().join(format!("{host}.v{VERSION}"))
}

// Extract the host alias from a marker filename. Accepts both the new
// versioned format (`<host>.v<MAJOR>.<MINOR>.<PATCH>`) and legacy bare
// markers (`<host>`) from pre-versioned releases. Skips session-cache
// sidecars (`.sessions`).
fn alias_from_marker(filename: &str) -> Option<&str> {
    if filename.ends_with(".sessions") {
        return None;
    }
    if let Some(idx) = filename.rfind(".v") {
        let suffix = &filename[idx + 2..];
        let parts: Vec<&str> = suffix.split('.').collect();
        if parts.len() == 3
            && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return Some(&filename[..idx]);
        }
    }
    // Legacy bare marker (pre-versioned release).
    Some(filename)
}

// Sorted, deduplicated list of known remote host aliases.
fn list_known_remotes() -> Vec<String> {
    let Ok(entries) = fs::read_dir(remotes_dir()) else {
        return vec![];
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|e| alias_from_marker(&e.file_name().to_string_lossy()).map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    out
}

// After a successful redeploy, drop any legacy bare marker and any older
// versioned markers for the same host. Idempotent.
fn cleanup_old_markers(host: &str) {
    let current = format!("{host}.v{VERSION}");
    let Ok(entries) = fs::read_dir(remotes_dir()) else { return; };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == current || name.ends_with(".sessions") {
            continue;
        }
        if alias_from_marker(&name).map(|a| a == host).unwrap_or(false) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn validate_name(name: &str) {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        eprintln!("Invalid session name: {name}");
        eprintln!("Use letters, numbers, hyphens, underscores, dots.");
        exit(1);
    }
}

// ── Terminal helpers ──────────────────────────────────────────────────────
fn get_winsize() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    unsafe { libc::ioctl(0, libc::TIOCGWINSZ as IoctlReq, &mut ws) };
    (ws.ws_row, ws.ws_col)
}

fn set_winsize(fd: RawFd, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as IoctlReq, &ws) };
}

fn make_raw() -> nix::Result<Termios> {
    let fd = unsafe { BorrowedFd::borrow_raw(0) };
    let saved = termios::tcgetattr(fd)?;
    let mut raw = saved.clone();
    termios::cfmakeraw(&mut raw);
    termios::tcsetattr(fd, SetArg::TCSADRAIN, &raw)?;
    Ok(saved)
}

fn restore_term(saved: &Termios) {
    let fd = unsafe { BorrowedFd::borrow_raw(0) };
    let _ = termios::tcsetattr(fd, SetArg::TCSADRAIN, saved);
}

// ── SIGWINCH handling ─────────────────────────────────────────────────────
static WINCH: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::Relaxed);
}

fn install_winch_handler() {
    let sa = SigAction::new(
        SigHandler::Handler(handle_winch),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    unsafe { sigaction(Signal::SIGWINCH, &sa) }.ok();
}

// ── Scrollback buffer ─────────────────────────────────────────────────────
const SCROLLBACK_SIZE: usize = 4 * 1024; // 4KB — about a screenful

struct Scrollback {
    data: Vec<u8>,
    cap: usize,
}

impl Scrollback {
    fn new(cap: usize) -> Self {
        Self { data: Vec::with_capacity(cap), cap }
    }

    fn push(&mut self, bytes: &[u8]) {
        if bytes.len() >= self.cap {
            self.data.clear();
            self.data.extend_from_slice(&bytes[bytes.len() - self.cap..]);
        } else if self.data.len() + bytes.len() > self.cap {
            let drop = self.data.len() + bytes.len() - self.cap;
            self.data.drain(..drop);
            self.data.extend_from_slice(bytes);
        } else {
            self.data.extend_from_slice(bytes);
        }
    }

    fn contents(&self) -> &[u8] {
        let d = &self.data;
        // Skip to the first newline to avoid replaying a partial escape sequence
        // that was clipped at the start of the ring buffer
        for (i, &b) in d.iter().enumerate() {
            if b == b'\n' {
                return &d[i + 1..];
            }
        }
        d
    }
}

// ── Daemon event loop ─────────────────────────────────────────────────────

/// Strip OSC escape sequences (\x1b]...\x07 or \x1b]...\x1b\\) from data.
/// These include terminal color queries, title changes, clipboard ops, etc.
/// Replaying them would cause the terminal to send responses that appear as
/// garbage input in the session.
fn strip_osc_sequences(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if i + 1 < data.len() && data[i] == 0x1b && data[i + 1] == b']' {
            // Skip OSC: \x1b] ... terminated by BEL (\x07) or ST (\x1b\\)
            i += 2;
            while i < data.len() {
                if data[i] == 0x07 {
                    i += 1;
                    break;
                }
                if i + 1 < data.len() && data[i] == 0x1b && data[i + 1] == b'\\' {
                    i += 2;
                    break;
                }
                i += 1;
            }
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

fn daemon_loop(master_raw: RawFd, listener: &UnixListener, child_pid: Pid, name: &str) {
    // Ignore SIGPIPE and SIGHUP (client disconnect shouldn't kill daemon)
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    };

    // Set master fd non-blocking
    unsafe {
        let flags = libc::fcntl(master_raw, libc::F_GETFL);
        libc::fcntl(master_raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let listener_raw = listener.as_raw_fd();
    let mut client: Option<UnixStream> = None;
    let mut buf = [0u8; BUF_SIZE];
    let mut scrollback = Scrollback::new(SCROLLBACK_SIZE);

    loop {
        // Check child status
        match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(_) => {}
            _ => break,
        }

        let client_raw = client.as_ref().map(|c| c.as_raw_fd()).unwrap_or(-1);

        let mut fds = [
            libc::pollfd { fd: master_raw, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: listener_raw, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: client_raw, events: libc::POLLIN, revents: 0 },
        ];
        let nfds: libc::nfds_t = if client.is_some() { 3 } else { 2 };

        let ret = unsafe { libc::poll(fds.as_mut_ptr(), nfds, 1000) };
        if ret < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // Accept new client (replaces existing)
        if fds[1].revents & libc::POLLIN != 0 {
            if let Ok((mut stream, _)) = listener.accept() {
                // Replay scrollback so the client sees recent output,
                // stripping OSC sequences that would trigger terminal responses
                let raw = scrollback.contents();
                let clean = strip_osc_sequences(raw);
                let _ = stream.write_all(&clean);
                client = Some(stream);
            }
        }

        // PTY output -> client (raw, no framing)
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let n = unsafe { libc::read(master_raw, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n > 0 {
                let data = &buf[..n as usize];
                scrollback.push(data);
                if let Some(ref mut c) = client {
                    if c.write_all(data).is_err() {
                        client = None;
                    }
                }
            } else if n == 0 {
                break;
            } else {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::WouldBlock {
                    break;
                }
            }
        }

        // Client -> PTY (framed messages)
        if client.is_some() && fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let disconnect = {
                let c = client.as_mut().unwrap();
                handle_client_msg(c, master_raw, child_pid)
            };
            if disconnect {
                client = None;
            }
        }
    }

    // Drain remaining PTY output to client
    if let Some(ref mut c) = client {
        loop {
            let n = unsafe { libc::read(master_raw, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 { break; }
            if c.write_all(&buf[..n as usize]).is_err() { break; }
        }
    }

    // Cleanup
    let _ = fs::remove_file(sock_path(name));
    let _ = fs::remove_file(meta_path(name));
    let _ = fs::remove_file(pid_path(name));
}

/// Returns true if client disconnected
fn handle_client_msg(client: &mut UnixStream, master_raw: RawFd, child: Pid) -> bool {
    let mut hdr = [0u8; 3];
    if client.read_exact(&mut hdr).is_err() {
        return true;
    }

    let msg_type = hdr[0];
    let len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;

    if len > BUF_SIZE {
        return true;
    }

    let mut payload = vec![0u8; len];
    if len > 0 && client.read_exact(&mut payload).is_err() {
        return true;
    }

    match msg_type {
        MSG_INPUT => {
            unsafe { libc::write(master_raw, payload.as_ptr() as *const _, len) };
        }
        MSG_WINCH => {
            if len >= 4 {
                let rows = u16::from_be_bytes([payload[0], payload[1]]);
                let cols = u16::from_be_bytes([payload[2], payload[3]]);
                set_winsize(master_raw, rows, cols);
                let _ = nix::sys::signal::kill(child, Signal::SIGWINCH);
            }
        }
        _ => {}
    }

    false
}

// ── Session creation ──────────────────────────────────────────────────────
fn create_session(name: &str, dir: &Path, shell: &str) -> io::Result<()> {
    fs::create_dir_all(sesh_dir())?;

    // Create sync pipe
    let (pipe_r, pipe_w) = unistd::pipe()
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    let pipe_r_raw = pipe_r.into_raw_fd();
    let pipe_w_raw = pipe_w.into_raw_fd();

    match unsafe { unistd::fork() }
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?
    {
        ForkResult::Child => {
            // ── Daemon process ──
            unsafe { libc::close(pipe_r_raw) };
            let _ = unistd::setsid();

            // Redirect stdio to /dev/null
            if let Ok(devnull) = fs::OpenOptions::new().read(true).write(true).open("/dev/null") {
                let null_fd = devnull.as_raw_fd();
                unsafe {
                    libc::dup2(null_fd, 0);
                    libc::dup2(null_fd, 1);
                    libc::dup2(null_fd, 2);
                }
            }

            // Create PTY
            let mut master_raw: RawFd = -1;
            let mut slave_raw: RawFd = -1;
            let ret = unsafe {
                libc::openpty(
                    &mut master_raw,
                    &mut slave_raw,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if ret < 0 {
                unsafe { libc::write(pipe_w_raw, b"E".as_ptr() as *const _, 1) };
                exit(1);
            }

            // Fork shell child
            let child_pid = match unsafe { unistd::fork() } {
                Ok(ForkResult::Child) => {
                    unsafe {
                        libc::close(master_raw);
                        libc::close(pipe_w_raw);
                    }
                    let _ = unistd::setsid();
                    unsafe {
                        libc::ioctl(slave_raw, libc::TIOCSCTTY as IoctlReq, 0);
                        libc::dup2(slave_raw, 0);
                        libc::dup2(slave_raw, 1);
                        libc::dup2(slave_raw, 2);
                        if slave_raw > 2 {
                            libc::close(slave_raw);
                        }
                    }
                    let _ = env::set_current_dir(dir);
                    let err = Command::new(shell).exec();
                    eprintln!("sesh: exec {shell}: {err}");
                    exit(1);
                }
                Ok(ForkResult::Parent { child }) => {
                    unsafe { libc::close(slave_raw) };
                    child
                }
                Err(_) => {
                    unsafe { libc::write(pipe_w_raw, b"E".as_ptr() as *const _, 1) };
                    exit(1);
                }
            };

            // Create socket
            let sock = sock_path(name);
            let _ = fs::remove_file(&sock);
            let listener = match UnixListener::bind(&sock) {
                Ok(l) => l,
                Err(_) => {
                    unsafe { libc::write(pipe_w_raw, b"E".as_ptr() as *const _, 1) };
                    exit(1);
                }
            };
            listener.set_nonblocking(true).ok();

            // Write metadata
            let _ = fs::write(meta_path(name), dir.to_string_lossy().as_bytes());
            let _ = fs::write(pid_path(name), format!("{}", unistd::getpid()));

            // Signal readiness
            unsafe {
                libc::write(pipe_w_raw, b"R".as_ptr() as *const _, 1);
                libc::close(pipe_w_raw);
            }

            // Run event loop (never returns normally)
            daemon_loop(master_raw, &listener, child_pid, name);
            exit(0);
        }
        ForkResult::Parent { .. } => {
            // ── Original process ──
            unsafe { libc::close(pipe_w_raw) };

            // Wait for daemon readiness
            let mut sig = [0u8; 1];
            let n = unsafe { libc::read(pipe_r_raw, sig.as_mut_ptr() as *mut _, 1) };
            unsafe { libc::close(pipe_r_raw) };

            if n != 1 || sig[0] != b'R' {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to create session",
                ));
            }

            // Attach as client
            run_client(name)
        }
    }
}

// ── Client (attach) ───────────────────────────────────────────────────────
fn run_client(name: &str) -> io::Result<()> {
    let mut stream = UnixStream::connect(sock_path(name))?;

    // Put terminal in raw mode
    let saved = make_raw().map_err(|e| io::Error::from_raw_os_error(e as i32))?;

    // Ensure terminal is restored on exit (including panic)
    struct Guard(Option<Termios>);
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(ref t) = self.0 {
                restore_term(t);
            }
        }
    }
    let mut guard = Guard(Some(saved.clone()));

    // Set up signals
    install_winch_handler();
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN); // SSH disconnect sends SIGHUP
    }

    // Send initial window size
    let (rows, cols) = get_winsize();
    send_winch(&mut stream, rows, cols)?;

    let stream_raw = stream.as_raw_fd();
    let mut buf = [0u8; BUF_SIZE];

    let result = loop {
        // Handle pending SIGWINCH
        if WINCH.swap(false, Ordering::Relaxed) {
            let (rows, cols) = get_winsize();
            if send_winch(&mut stream, rows, cols).is_err() {
                break Ok(());
            }
        }

        let mut fds = [
            libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: stream_raw, events: libc::POLLIN, revents: 0 },
        ];

        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 500) };
        if ret < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break Ok(());
        }

        // stdin -> master
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break Ok(()); // Terminal gone (SSH dropped)
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                break Ok(());
            }
            let n = n as usize;

            // Check for detach key
            if let Some(pos) = buf[..n].iter().position(|&b| b == DETACH_KEY) {
                if pos > 0 {
                    let _ = send_input(&mut stream, &buf[..pos]);
                }
                break Ok(());
            }

            if send_input(&mut stream, &buf[..n]).is_err() {
                break Ok(());
            }
        }

        // master -> stdout (raw, no framing)
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let n = unsafe { libc::read(stream_raw, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                break Ok(());
            }
            // Loop on write — stdout can return partial writes (macOS PIPE_BUF=512).
            // Dropping bytes mid-escape-sequence corrupts terminal state.
            let mut off = 0usize;
            let total = n as usize;
            while off < total {
                let written = unsafe {
                    libc::write(1, buf[off..].as_ptr() as *const _, total - off)
                };
                if written > 0 {
                    off += written as usize;
                } else if written < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break; // stdout truly broken
                }
            }
            if off < total {
                break Ok(()); // stdout broken
            }
        }
    };

    // Restore terminal (guard also handles this, but be explicit)
    guard.0.take().map(|t| restore_term(&t));

    result
}

// ── Session management ────────────────────────────────────────────────────
fn create_or_attach(name: &str, dir: Option<&str>) -> io::Result<()> {
    let sock = sock_path(name);

    // If socket exists and is live, attach
    if sock.exists() {
        if UnixStream::connect(&sock).is_ok() {
            if dir.is_some() {
                eprintln!("Session '{name}' already exists. Attaching (ignoring dir).");
            }
            return run_client(name);
        }
        // Stale socket, clean up
        let _ = fs::remove_file(&sock);
        let _ = fs::remove_file(meta_path(name));
        let _ = fs::remove_file(pid_path(name));
    }

    // No local session found — if no dir specified, search remotes before creating
    if dir.is_none() {
        let remote_hosts = find_remote_sessions(name);
        match remote_hosts.len() {
            0 => {} // Not found anywhere, fall through to create locally
            1 => {
                // Found on exactly one remote
                let host = &remote_hosts[0];
                eprintln!("Connecting to '{name}' on {host}...");
                ssh_attach(host, &[name]);
            }
            _ => {
                // Found on multiple remotes, prompt
                eprintln!("Session '{name}' found on multiple hosts:");
                for (i, host) in remote_hosts.iter().enumerate() {
                    eprintln!("  {}) {}", i + 1, host);
                }
                eprint!("Select [1-{}]: ", remote_hosts.len());
                let idx = read_selection(remote_hosts.len());
                match idx {
                    Some(i) => {
                        let host = &remote_hosts[i];
                        ssh_attach(host, &[name]);
                    }
                    None => {
                        eprintln!("Invalid selection.");
                        exit(1);
                    }
                }
            }
        }
    }

    // Resolve directory
    let dir_path = if let Some(d) = dir {
        fs::canonicalize(d).map_err(|_| {
            io::Error::new(io::ErrorKind::NotFound, format!("Directory not found: {d}"))
        })?
    } else {
        env::current_dir()?
    };

    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
    create_session(name, &dir_path, &shell)
}

/// Search all known remotes for a session with the given name.
fn find_remote_sessions(name: &str) -> Vec<String> {
    let hosts = list_known_remotes();
    if hosts.is_empty() {
        return vec![];
    }

    let name = name.to_string();
    let handles: Vec<_> = hosts
        .into_iter()
        .map(|host| {
            let name = name.clone();
            std::thread::spawn(move || {
                // Try live query first
                let output = Command::new("ssh")
                    .args([
                        "-o", "ConnectTimeout=5",
                        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                        &host,
                        "~/.local/bin/sesh", "list",
                    ])
                    .output()
                    .ok();

                let text = match output {
                    Some(out) if out.status.success() => {
                        let t = String::from_utf8_lossy(&out.stdout).to_string();
                        let _ = fs::write(remote_cache_path(&host), &t);
                        t
                    }
                    _ => {
                        // Fall back to cache
                        fs::read_to_string(remote_cache_path(&host)).unwrap_or_default()
                    }
                };

                for line in text.lines() {
                    // Only consider session-data lines (indented with two spaces).
                    // Skips "No active sessions." help text from older remotes.
                    if !line.starts_with("  ") {
                        continue;
                    }
                    let first = line.split_whitespace().next().unwrap_or("");
                    if first == name {
                        return Some(host);
                    }
                }
                None
            })
        })
        .collect();

    let mut found: Vec<String> = handles
        .into_iter()
        .filter_map(|h| h.join().ok().flatten())
        .collect();
    found.sort();
    found
}

/// Read a 1-based numeric selection from /dev/tty. Returns 0-based index.
fn read_selection(max: usize) -> Option<usize> {
    let mut tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let mut input = String::new();
    let mut buf = [0u8; 1];
    loop {
        if tty.read(&mut buf).ok()? == 0 {
            break;
        }
        if buf[0] == b'\n' {
            break;
        }
        input.push(buf[0] as char);
    }
    let idx: usize = input.trim().parse().ok()?;
    if idx >= 1 && idx <= max {
        Some(idx - 1)
    } else {
        None
    }
}

fn list_local_sessions() -> Vec<(String, String)> {
    let dir = sesh_dir();
    if !dir.exists() {
        return vec![];
    }

    let mut sessions = vec![];
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(true, |e| e != "sock") {
                continue;
            }
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            // Check daemon liveness via PID file (NOT socket connect,
            // which would replace the active client and disconnect users)
            if is_daemon_alive(&name) {
                let dir_str = fs::read_to_string(meta_path(&name)).unwrap_or_default();
                sessions.push((name, dir_str.trim().to_string()));
            } else {
                let _ = fs::remove_file(&path);
                let _ = fs::remove_file(meta_path(&name));
                let _ = fs::remove_file(pid_path(&name));
            }
        }
    }
    sessions.sort();
    sessions
}

/// Check if a session's daemon process is still running.
/// Uses kill(pid, 0) which checks process existence without sending a signal.
fn is_daemon_alive(name: &str) -> bool {
    if let Ok(pid_str) = fs::read_to_string(pid_path(name)) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            return unsafe { libc::kill(pid, 0) } == 0;
        }
    }
    false
}

fn list_all() {
    let mut has_output = false;
    let mut stdout = io::stdout();

    let local = list_local_sessions();
    let hosts = list_known_remotes();
    let has_remotes = !hosts.is_empty();

    if !local.is_empty() {
        if has_remotes {
            println!("local:");
        }
        for (name, dir) in &local {
            println!("  {:<20} {}", name, dir);
        }
        has_output = true;
    }

    // Query remotes in parallel, streaming results as they arrive
    if has_remotes {
        let num_remotes = hosts.len();

        // Print initial progress line
        println!("\x1b[2m[0/{num_remotes} remotes]\x1b[0m");
        let _ = stdout.flush();

        // Spawn threads that send results via channel
        let (tx, rx) = mpsc::channel();
        for host in hosts {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let result = query_remote_host(&host);
                let _ = tx.send((host, result));
            });
        }
        drop(tx);

        let mut completed = 0;
        for (host, result) in rx {
            completed += 1;

            // Move up 1 line and clear (overwrite progress)
            print!("\x1b[1A\x1b[K");

            // Print separator if needed
            if has_output { println!(); }

            // Print result
            match result {
                Ok(Some(text)) => {
                    println!("{host}:");
                    print!("{text}");
                }
                Ok(None) => {
                    println!("{host}: \x1b[2m(no sessions)\x1b[0m");
                }
                Err(reason) => {
                    let cache = remote_cache_path(&host);
                    if let Ok(cached) = fs::read_to_string(&cache) {
                        if !cached.trim().is_empty() {
                            println!("{host}: \x1b[2m({reason}, showing cached)\x1b[0m");
                            for line in cached.lines() {
                                if !line.trim().is_empty() {
                                    println!("{line}");
                                }
                            }
                        } else {
                            println!("{host}: \x1b[2m({reason})\x1b[0m");
                        }
                    } else {
                        println!("{host}: \x1b[2m({reason})\x1b[0m");
                    }
                }
            }
            has_output = true;

            // Print updated progress (if not done)
            if completed < num_remotes {
                println!("\x1b[2m[{completed}/{num_remotes} remotes]\x1b[0m");
            }
            let _ = stdout.flush();
        }
    }

    if !has_output {
        // Only show the friendly empty-state message in an interactive terminal.
        // When `sesh list` is invoked over SSH (e.g. by another sesh querying
        // this host as a remote), stdout is a pipe — emit nothing, so the
        // caller sees "(no sessions)" rather than the help text.
        if unsafe { libc::isatty(1) } == 1 {
            println!("No active sessions.");
            println!("Run `sesh help` for usage.");
        }
    }
}

/// Query a remote host for sessions. Returns Ok(Some(text)), Ok(None), or Err(reason).
fn query_remote_host(host: &str) -> Result<Option<String>, String> {
    let output = Command::new("ssh")
        .args([
            "-o", "ConnectTimeout=5",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            host,
            "~/.local/bin/sesh", "list",
        ])
        .output()
        .ok();

    match output {
        Some(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            // Only consider lines that look like session entries — indented
            // with two spaces (`  name  dir`). Older remotes (pre-isatty
            // fix) emit "No active sessions.\nRun `sesh help` for usage."
            // when empty; treat that as no sessions, not as session data.
            let has_sessions = text.lines().any(|l| l.starts_with("  ") && !l.trim().is_empty());
            if has_sessions {
                let _ = fs::write(remote_cache_path(host), &text);
                Ok(Some(text))
            } else {
                let _ = fs::write(remote_cache_path(host), "");
                Ok(None)
            }
        }
        Some(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let stdout_text = String::from_utf8_lossy(&out.stdout).to_string();
            let reason = stderr.lines()
                .chain(stdout_text.lines())
                .find(|l| !l.trim().is_empty() && !l.contains("Warning:"))
                .unwrap_or("connection failed")
                .trim()
                .to_string();
            Err(reason)
        }
        None => Err("connection failed".to_string()),
    }
}

fn kill_session(name: &str) {
    // Try local first
    if sock_path(name).exists() {
        if let Ok(pid_str) = fs::read_to_string(pid_path(name)) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                let _ = nix::sys::signal::kill(Pid::from_raw(pid), Signal::SIGTERM);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));

        let _ = fs::remove_file(sock_path(name));
        let _ = fs::remove_file(meta_path(name));
        let _ = fs::remove_file(pid_path(name));

        println!("Killed: {name}");
        return;
    }

    // Not local — search remotes
    let remote_hosts = find_remote_sessions(name);
    match remote_hosts.len() {
        0 => {
            eprintln!("No session: {name}");
            exit(1);
        }
        1 => {
            let host = &remote_hosts[0];
            let status = Command::new("ssh")
                .args([host, "~/.local/bin/sesh", "kill", name])
                .status();
            exit(status.map_or(1, |s| s.code().unwrap_or(1)));
        }
        _ => {
            eprintln!("Session '{name}' found on multiple hosts:");
            for (i, host) in remote_hosts.iter().enumerate() {
                eprintln!("  {}) {}", i + 1, host);
            }
            eprint!("Select [1-{}]: ", remote_hosts.len());
            match read_selection(remote_hosts.len()) {
                Some(i) => {
                    let host = &remote_hosts[i];
                    let status = Command::new("ssh")
                        .args([host, "~/.local/bin/sesh", "kill", name])
                        .status();
                    exit(status.map_or(1, |s| s.code().unwrap_or(1)));
                }
                None => {
                    eprintln!("Invalid selection.");
                    exit(1);
                }
            }
        }
    }
}

// ── Remote support ────────────────────────────────────────────────────────
const NPM_PACKAGE: &str = "@bobstrogg/sesh";
const GITHUB_RELEASE_URL: &str = "https://github.com/BobStrogg/sesh/releases/latest/download";

/// SSH to a remote host and attach to a session, with auto-reconnect on drops.
/// Exit code 0 (clean detach) exits normally. Non-zero (connection lost) retries.
/// Ctrl-C stops the retry loop.
fn ssh_attach(host: &str, remote_args: &[&str]) -> ! {
    use std::process::Stdio;
    let mut first = true;
    loop {
        let mut cmd = Command::new("ssh");
        cmd.arg("-t").arg(host).arg("~/.local/bin/sesh");
        for arg in remote_args {
            cmd.arg(arg);
        }
        // Suppress SSH's own stderr ("Broken pipe", "Connection closed", etc.)
        // on reconnect attempts — we show our own message instead.
        if !first {
            cmd.stderr(Stdio::null());
        }
        first = false;
        let status = cmd.status();

        match status {
            Ok(s) if s.code() == Some(0) => exit(0), // Clean detach
            Ok(s) => {
                let code = s.code().unwrap_or(1);
                eprintln!("\r\nConnection lost (exit {code}). Reconnecting in 3s... (Ctrl-C to abort)");
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            Err(e) => {
                eprintln!("\r\nSSH error: {e}. Reconnecting in 3s... (Ctrl-C to abort)");
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        }
    }
}

/// Detect remote OS/arch and return the binary name (e.g. "sesh-linux-x86_64").
fn detect_remote_platform(host: &str) -> Option<String> {
    use std::process::Stdio;
    let output = Command::new("ssh")
        .args(["-o", "ConnectTimeout=5", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", host, "uname -s; uname -m"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 2 {
        return None;
    }
    let os = match lines[0].trim().to_lowercase().as_str() {
        "linux" => "linux",
        "darwin" => "darwin",
        _ => return None,
    };
    let arch = match lines[1].trim() {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        _ => return None,
    };
    Some(format!("sesh-{os}-{arch}"))
}

/// Deploy the correct sesh binary to a remote host.
fn deploy_to_remote(host: &str) -> bool {
    // Detect remote platform
    let binary_name = match detect_remote_platform(host) {
        Some(name) => name,
        None => {
            eprintln!("Could not detect remote platform for {host}");
            return false;
        }
    };

    // Method 1: Install via npm on the remote (preferred, no auth needed)
    let npm_install = Command::new("ssh")
        .stderr(std::process::Stdio::null())
        .args([
            "-o", "ConnectTimeout=10",
            host,
            &format!(
                "command -v npm >/dev/null 2>&1 && npm install -g {NPM_PACKAGE} 2>&1 || \
                 command -v npx >/dev/null 2>&1 && npx {NPM_PACKAGE} 2>&1 || \
                 echo 'SESH_NPM_FAIL'"
            ),
        ])
        .output();

    if let Ok(out) = npm_install {
        let text = String::from_utf8_lossy(&out.stdout);
        if out.status.success() && !text.contains("SESH_NPM_FAIL") {
            // Ensure it's also at ~/.local/bin/sesh for consistency
            let _ = Command::new("ssh")
                .stderr(std::process::Stdio::null())
                .args([host, "mkdir -p ~/.local/bin && command -v sesh >/dev/null && ln -sf $(command -v sesh) ~/.local/bin/sesh 2>/dev/null || true"])
                .status();
            return true;
        }
    }
    eprintln!("  npm not available on remote, trying GitHub release...");

    // Method 2: Download from GitHub releases via curl/wget
    let download_cmd = format!(
        "mkdir -p ~/.local/bin && \
         (command -v curl >/dev/null 2>&1 && curl -fsSL -o ~/.local/bin/sesh {GITHUB_RELEASE_URL}/{binary_name} || \
          command -v wget >/dev/null 2>&1 && wget -qO ~/.local/bin/sesh {GITHUB_RELEASE_URL}/{binary_name} || \
          echo 'SESH_DOWNLOAD_FAIL') && \
         chmod +x ~/.local/bin/sesh"
    );
    let download = Command::new("ssh")
        .stderr(std::process::Stdio::null())
        .args(["-o", "ConnectTimeout=10", host, &download_cmd])
        .output();

    if let Ok(out) = download {
        let text = String::from_utf8_lossy(&out.stdout);
        if out.status.success() && !text.contains("SESH_DOWNLOAD_FAIL") {
            return true;
        }
    }
    eprintln!("  GitHub download failed");

    // Method 3: Fallback — copy local binary ONLY if same platform
    let local_os = std::env::consts::OS;
    let local_arch = std::env::consts::ARCH;
    let local_platform = format!(
        "{}-{}",
        if local_os == "macos" { "darwin" } else { local_os },
        if local_arch == "aarch64" { "aarch64" } else { local_arch }
    );
    let remote_platform = binary_name
        .strip_prefix("sesh-")
        .unwrap_or(&binary_name);

    if local_platform != remote_platform {
        eprintln!("  Cannot deploy: local is {local_platform}, remote is {remote_platform}");
        eprintln!("  Fix: install curl, wget, or npm on the remote host");
        return false;
    }

    eprintln!("  Copying local binary...");
    let tmp = format!("/tmp/sesh-deploy-{}", std::process::id());
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("sesh"));
    let _ = fs::copy(&exe, &tmp);
    deploy_file_to_remote(host, &tmp)
}

/// SCP a local file to the remote's ~/.local/bin/sesh
fn deploy_file_to_remote(host: &str, local_path: &str) -> bool {
    use std::process::Stdio;
    let null = || Stdio::null();
    let _ = Command::new("ssh").args([host, "mkdir", "-p", "~/.local/bin"]).stderr(null()).status();
    let _ = Command::new("ssh").args([host, "rm", "-f", "~/.local/bin/sesh"]).stderr(null()).status();
    let scp = Command::new("scp").args(["-q", local_path, &format!("{host}:.local/bin/sesh")]).stderr(null()).status();
    let _ = Command::new("ssh").args([host, "chmod", "+x", "~/.local/bin/sesh"]).stderr(null()).status();
    let _ = fs::remove_file(local_path);
    scp.map_or(false, |s| s.success())
}

fn ensure_remote_sesh(host: &str) {
    let marker = remote_marker_path(host);
    if marker.exists() {
        // We've already deployed *this* version of sesh to this host.
        return;
    }

    // Either the remote has never seen sesh, or it has an older version.
    // Either way, push our current binary so the remote and local stay in
    // sync. Older markers (legacy bare or older `.v*`) are cleaned up
    // after a successful deploy.
    eprintln!("Deploying sesh to {host}...");
    if !deploy_to_remote(host) {
        return;
    }
    eprintln!("Done.");

    let _ = fs::create_dir_all(remotes_dir());
    let _ = fs::write(&marker, "");
    cleanup_old_markers(host);
}

fn deploy_remote(host: &str) {
    eprintln!("Deploying sesh to {host}...");
    if !deploy_to_remote(host) {
        eprintln!("Failed to deploy to {host}");
        exit(1);
    }
    let _ = fs::create_dir_all(remotes_dir());
    let _ = fs::write(remote_marker_path(host), "");
    cleanup_old_markers(host);
    eprintln!("Done.");
}

fn upgrade_all_remotes() {
    let hosts = list_known_remotes();
    if hosts.is_empty() {
        eprintln!("No known remotes.");
        return;
    }

    let mut ok = 0;
    let mut fail = 0;
    for host in &hosts {
        eprintln!("Deploying sesh to {host}...");
        if deploy_to_remote(host) {
            eprintln!("  OK");
            let _ = fs::write(remote_marker_path(host), "");
            cleanup_old_markers(host);
            ok += 1;
        } else {
            eprintln!("  FAILED");
            fail += 1;
        }
    }
    eprintln!("Upgraded {ok}/{} remotes.", ok + fail);
}

fn remote_dispatch(host: &str, args: &[String]) {
    ensure_remote_sesh(host);

    if args.is_empty() || matches!(args[0].as_str(), "list" | "ls") {
        let output = Command::new("ssh")
            .args(["-o", "ConnectTimeout=5", host, "~/.local/bin/sesh", "list"])
            .output()
            .ok();
        match output {
            Some(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                if text.trim().is_empty() {
                    println!("{host}: (no sessions)");
                } else {
                    println!("{host}:");
                    print!("{text}");
                }
            }
            None => println!("{host}: (unreachable)"),
        }
        return;
    }

    match args[0].as_str() {
        "kill" | "rm" => {
            if args.len() < 2 {
                eprintln!("Usage: sesh @{host} kill <name>");
                exit(1);
            }
            let status = Command::new("ssh")
                .args([host, "~/.local/bin/sesh", "kill", &args[1]])
                .status();
            exit(status.map_or(1, |s| s.code().unwrap_or(1)));
        }
        "help" | "-h" | "--help" => show_help(),
        _ => {
            let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
            ssh_attach(host, &str_args);
        }
    }
}

// ── Export / Import ───────────────────────────────────────────────────────

/// Export current session layout as a simple config.
/// Format: one line per session: "host\tname\tdir"
/// Local sessions use "local" as the host.
fn export_sessions() {
    // Local sessions
    let local = list_local_sessions();
    for (name, dir) in &local {
        println!("local\t{name}\t{dir}");
    }

    // Remote sessions (query in parallel)
    let hosts = list_known_remotes();
    if !hosts.is_empty() {

        let handles: Vec<_> = hosts
            .into_iter()
            .map(|host| {
                std::thread::spawn(move || {
                    let output = Command::new("ssh")
                        .args([
                            "-o", "ConnectTimeout=3",
                            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                            &host,
                            "~/.local/bin/sesh", "list",
                        ])
                        .output()
                        .ok()?;
                    let text = String::from_utf8_lossy(&output.stdout).to_string();
                    if text.trim().is_empty() {
                        None
                    } else {
                        Some((host, text))
                    }
                })
            })
            .collect();

        for handle in handles {
            if let Ok(Some((host, text))) = handle.join() {
                for line in text.lines() {
                    // Only consider session-data lines (indented with two spaces).
                    // Skips "No active sessions." help text from older remotes.
                    if !line.starts_with("  ") {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let name = parts[0];
                        let dir = parts[1..].join(" ");
                        println!("{host}\t{name}\t{dir}");
                    }
                }
            }
        }
    }
}

/// Import sessions from a config file (or stdin if "-").
/// Creates sessions that don't already exist.
fn import_sessions(file: &str) {
    let content = if file == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap_or_default();
        buf
    } else {
        fs::read_to_string(file).unwrap_or_else(|e| {
            eprintln!("sesh: {file}: {e}");
            exit(1);
        })
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 3 {
            eprintln!("Skipping malformed line: {line}");
            continue;
        }

        let host = parts[0];
        let name = parts[1];
        let dir = parts[2];

        if host == "local" {
            eprintln!("Creating local session: {name} in {dir}");
            let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
            if let Ok(dir_path) = fs::canonicalize(dir) {
                let _ = create_session(name, &dir_path, &shell);
            } else {
                eprintln!("  Skipped (directory not found: {dir})");
            }
        } else {
            // Ensure remote is set up, then create session
            ensure_remote_sesh(host);
            eprintln!("Creating remote session: {name} on {host} in {dir}");
            let _ = Command::new("ssh")
                .args([host, "~/.local/bin/sesh", name, dir])
                .status();
            // Detach immediately (the remote sesh will create and daemonize)
        }
    }
    eprintln!("Import complete.");
}

// ── CLI ───────────────────────────────────────────────────────────────────
fn show_help() {
    println!(
        "\
Usage:
  sesh                       List all sessions (local + remotes)
  sesh <name> [dir]          Create or attach to a local session
  sesh kill <name>           Kill a local session

  sesh @<host>               List sessions on a remote host
  sesh @<host> <name> [dir]  Create or attach to a remote session
  sesh @<host> kill <name>   Kill a remote session

  sesh deploy @<host>        Deploy/update sesh on a remote host
  sesh upgrade               Redeploy sesh to all known remotes
  sesh export                Export session layout to stdout
  sesh import [file]         Recreate sessions from export (- for stdin)
  sesh completions <shell>   Print shell completions (bash, zsh)
  sesh help                  Show this help
  sesh version               Print version (--version, -V)

Detach with Ctrl-\\
Hosts use SSH config names (e.g. \"Host prod\" in ~/.ssh/config).
Remote dir paths are on the remote — quote ~ to prevent local expansion."
    );
}

fn print_completions(shell: &str) {
    match shell {
        "bash" => print!(
            r##"_sesh() {{
    local cur prev words cword
    _init_completion || return

    local cmds="list ls kill rm deploy upgrade export import completions help version"

    if [[ $cword -eq 1 ]]; then
        local sessions
        sessions="$(sesh --names 2>/dev/null)"
        local hosts
        hosts="$(sesh --hosts 2>/dev/null)"
        COMPREPLY=( $(compgen -W "$cmds $sessions $hosts" -- "$cur") )
        return
    fi

    case "${{words[1]}}" in
        kill|rm)
            local sessions
            sessions="$(sesh --names 2>/dev/null)"
            COMPREPLY=( $(compgen -W "$sessions" -- "$cur") )
            ;;
        deploy)
            local hosts
            hosts="$(sesh --hosts 2>/dev/null)"
            COMPREPLY=( $(compgen -W "$hosts" -- "$cur") )
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
            ;;
        @*)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "kill list ls" -- "$cur") )
            fi
            ;;
    esac
}}
complete -F _sesh sesh
"##
        ),
        "zsh" => print!(
            r##"#compdef sesh

_sesh_sessions() {{
    local -a sessions
    sessions=(${{(f)"$(sesh --names 2>/dev/null)"}})
    compadd -a sessions
}}

_sesh_hosts() {{
    local -a hosts
    hosts=(${{(f)"$(sesh --hosts 2>/dev/null)"}})
    compadd -a hosts
}}

_sesh() {{
    local -a commands
    commands=(list ls kill rm deploy upgrade export import completions help version)

    if (( CURRENT == 2 )); then
        _alternative \
            'commands:command:compadd -a commands' \
            'sessions:session:_sesh_sessions' \
            'hosts:host:_sesh_hosts'
        return
    fi

    case "${{words[2]}}" in
        kill|rm)
            _sesh_sessions
            ;;
        deploy)
            _sesh_hosts
            ;;
        completions)
            compadd bash zsh
            ;;
        @*)
            if (( CURRENT == 3 )); then
                compadd kill list ls
            fi
            ;;
    esac
}}

_sesh "$@"
"##
        ),
        _ => {
            eprintln!("Unsupported shell: {shell}");
            eprintln!("Usage: sesh completions <bash|zsh>");
            exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        None | Some("list") | Some("ls") => list_all(),
        Some("kill") | Some("rm") => {
            if args.len() < 2 {
                eprintln!("Usage: sesh kill <name>");
                exit(1);
            }
            validate_name(&args[1]);
            kill_session(&args[1]);
        }
        Some("deploy") => {
            if args.len() < 2 || !args[1].starts_with('@') {
                eprintln!("Usage: sesh deploy @<host>");
                exit(1);
            }
            deploy_remote(&args[1][1..]);
        }
        Some("upgrade") => upgrade_all_remotes(),
        Some("help" | "-h" | "--help") => show_help(),
        Some("version" | "-V" | "--version") => println!("sesh {VERSION}"),
        Some("export") => export_sessions(),
        Some("import") => {
            let file = args.get(1).map(String::as_str).unwrap_or("-");
            import_sessions(file);
        }
        Some("completions") => {
            let shell = args.get(1).map(String::as_str).unwrap_or("bash");
            print_completions(shell);
        }
        Some("--names") => {
            for (name, _) in list_local_sessions() {
                println!("{name}");
            }
        }
        Some("--hosts") => {
            for alias in list_known_remotes() {
                println!("@{alias}");
            }
        }
        Some(s) if s.starts_with('@') => {
            let host = &s[1..];
            if host.is_empty() {
                eprintln!("Usage: sesh @<host> [command]");
                exit(1);
            }
            remote_dispatch(host, &args[1..]);
        }
        Some(s) if s.starts_with('-') => {
            eprintln!("Unknown option: {s}");
            show_help();
            exit(1);
        }
        Some(name) => {
            validate_name(name);
            let dir = args.get(1).map(String::as_str);
            if let Err(e) = create_or_attach(name, dir) {
                eprintln!("sesh: {e}");
                exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::alias_from_marker;

    #[test]
    fn parses_versioned_marker() {
        assert_eq!(alias_from_marker("host1.example.com.v0.2.6"), Some("host1.example.com"));
        assert_eq!(alias_from_marker("host.v10.20.30"), Some("host"));
    }

    #[test]
    fn accepts_legacy_bare_marker() {
        assert_eq!(alias_from_marker("host1.example.com"), Some("host1.example.com"));
        assert_eq!(alias_from_marker("simple-host"), Some("simple-host"));
    }

    #[test]
    fn skips_session_cache_sidecars() {
        assert_eq!(alias_from_marker("host1.example.com.sessions"), None);
        assert_eq!(alias_from_marker("anything.sessions"), None);
    }

    #[test]
    fn rejects_malformed_version_suffix() {
        // not 3 dotted segments
        assert_eq!(alias_from_marker("host.v0.2"), Some("host.v0.2"));
        // non-numeric segments — falls through to legacy bare marker
        assert_eq!(alias_from_marker("host.vfoo.bar.baz"), Some("host.vfoo.bar.baz"));
        // empty segments
        assert_eq!(alias_from_marker("host.v..2"), Some("host.v..2"));
    }

    #[test]
    fn handles_alias_with_dots() {
        // FQDN-style alias should round-trip cleanly
        assert_eq!(
            alias_from_marker("a.b.c.d.v1.2.3"),
            Some("a.b.c.d"),
        );
    }
}
