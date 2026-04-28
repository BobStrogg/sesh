const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

// macOS: strip quarantine xattr and ad-hoc sign the platform binary so
// Gatekeeper doesn't kill the unsigned binary with SIGKILL on first run.
// (The wrapper script picks the right binary at runtime; we only need to
//  sign the one matching this machine's platform.)
if (os.platform() === "darwin") {
  const arch = os.arch() === "arm64" ? "aarch64" : "x86_64";
  const bin = path.join(__dirname, "bin", `sesh-darwin-${arch}`);
  if (fs.existsSync(bin)) {
    try { execSync(`xattr -d com.apple.quarantine "${bin}"`, { stdio: "ignore" }); } catch {}
    try { execSync(`codesign -s - -f "${bin}"`, { stdio: "ignore" }); } catch {}
  }
}

// Set up shell completions
try {
  const shell = path.basename(process.env.SHELL || "");
  const home = os.homedir();
  let rc, line;

  if (shell === "bash") {
    rc = path.join(home, ".bashrc");
    line = 'eval "$(sesh completions bash)"';
  } else if (shell === "zsh") {
    // Try .zshrc first, fall back to .zprofile
    const candidates = [".zshrc", ".zprofile", ".zshenv"];
    line = 'eval "$(sesh completions zsh)"';
    rc = null;
    for (const f of candidates) {
      const p = path.join(home, f);
      try {
        fs.accessSync(p, fs.constants.W_OK);
        rc = p;
        break;
      } catch {
        // Try next
        try {
          // File doesn't exist — try to create
          if (!fs.existsSync(p)) {
            rc = p;
            break;
          }
        } catch {}
      }
    }
  }

  if (rc && line) {
    const content = fs.existsSync(rc) ? fs.readFileSync(rc, "utf8") : "";
    if (!content.includes("sesh completions")) {
      fs.appendFileSync(rc, `\n${line}\n`);
      console.log(`Added tab-completion to ${rc}`);
    }
  }
} catch {}
