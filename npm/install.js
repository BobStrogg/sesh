const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const PLATFORM_MAP = {
  "linux-x64": "sesh-linux-x86_64",
  "linux-arm64": "sesh-linux-aarch64",
  "darwin-x64": "sesh-darwin-x86_64",
  "darwin-arm64": "sesh-darwin-aarch64",
};

const key = `${os.platform()}-${os.arch()}`;
const binary = PLATFORM_MAP[key];

if (!binary) {
  console.error(`sesh: unsupported platform ${key}`);
  process.exit(1);
}

const binDir = path.join(__dirname, "bin");
const src = path.join(binDir, binary);
const dest = path.join(binDir, "sesh");

if (!fs.existsSync(src)) {
  console.error(`sesh: binary not found: ${src}`);
  process.exit(1);
}

// Copy platform binary to the `sesh` entry point
fs.copyFileSync(src, dest);
fs.chmodSync(dest, 0o755);

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

console.log(`Installed sesh for ${key}`);
