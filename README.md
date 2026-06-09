# ubuntu-setup

A single Bash script (`setup.sh`) that provisions a fresh Ubuntu workstation into
a ready-to-use development machine, and restores your personal secrets (VPN, SSH
keys, `.env`) from encrypted blobs carried on the same USB stick.

The script is designed to live on a USB drive alongside its encrypted blobs. It
locates itself wherever the USB is mounted, so it works no matter where it's run
from. Every step is idempotent — re-running it on an already-configured machine
is a safe no-op and won't even prompt for your passphrase.

## Usage

```bash
# On a NEW machine — install everything and restore your secrets:
./setup.sh

# On YOUR machine — capture your secrets into encrypted blobs on the USB:
./setup.sh prepare
```

## What it installs & configures

- **Shells** — installs Fish, sets it as the login shell, and keeps Bash as a
  fully-configured fallback (`~/.bashrc` and `~/.config/fish/config.fish`).
- **Fisher + Bass** — Fish plugin manager and Bash-compatibility shim (needed so
  Fish can source Nix's Bash init scripts cleanly).
- **CLI tooling** — `curl`, `wget`, `git`, `ripgrep`, `gnupg`, `unzip`,
  `xz-utils`, `glab`, `gh`, `wl-clipboard`, `xclip`, and the GNOME Shell
  extension manager.
- **Claude Code** — installed via the official installer if not already present.
- **Docker** — Docker Engine, CLI, Buildx, Compose v2, plus Lazydocker (terminal
  UI). Adds your user to the `docker` group so `sudo` isn't needed for containers.
- **Nix / devenv / direnv** — path initialization and `direnv` hooks wired into
  both shells.
- **Neovim** — installed and aliased as `vim` in both shells.
- **`clip` alias** — resolves to `wl-copy` on Wayland or `xclip -sel clip` on X11
  at shell startup.
- **GNOME keyboard shortcuts** — `Super+Enter` → terminal, `Super+B` → browser,
  `Super+S` → settings, `Super+Q` → close window. Uses stable, descriptive slots
  so re-runs overwrite only these shortcuts and never disturb your own.
- **VPN** — L2TP/IPsec NetworkManager plugin, and installs your VPN connection
  from the encrypted config.

## Encrypted secrets

`setup.sh prepare` bundles three things into AES-256 GPG blobs stored next to the
script on the USB. The plaintext never lands on the USB unencrypted — a stolen
USB only ever holds the encrypted blobs, useless without your passphrase.

| Blob               | Contents                                   |
| ------------------ | ------------------------------------------ |
| `vpn.conf.gpg`     | L2TP/IPsec VPN connection details          |
| `ssh.keys.tar.gpg` | Your `~/.ssh/id_rsa` keypair               |
| `env.gpg`          | Your `~/.env` file                         |

A **single shared passphrase** protects all three blobs. It's prompted once per
run (read directly from the terminal, passed to GPG over a dedicated file
descriptor so it never appears in the process list) and reused for every blob.
When a blob already exists, a newly entered passphrase is verified against it, so
all blobs are guaranteed to stay on the same passphrase.

On a fresh machine, `./setup.sh` works out what actually needs restoring *before*
asking for a passphrase: an already-installed VPN or existing SSH keys are
detected and skipped, so a fully-configured machine is never prompted at all.

The `.gitignore` excludes `*.gpg`, so the encrypted blobs are never committed to
this repository — they travel on the USB only.
