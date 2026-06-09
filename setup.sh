#!/usr/bin/env bash

set -e

# Locate this script (and the encrypted VPN config beside it) wherever the USB
# is mounted, so paths work no matter where it's run from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPN_BLOB="$SCRIPT_DIR/vpn.conf.gpg"
SSH_BLOB="$SCRIPT_DIR/ssh.keys.tar.gpg"
ENV_BLOB="$SCRIPT_DIR/env.gpg"
export GPG_TTY="${GPG_TTY:-$(tty 2>/dev/null || true)}"

# --- Shared passphrase for all encrypted blobs --------------------------------
# One passphrase protects every blob (VPN + SSH + .env). It's prompted once per
# run and reused for all of them. gpg reads it from a dedicated file descriptor
# (loopback pinentry) so it never appears in the process list. When a blob already
# exists (e.g. VPN was set up on an earlier run), a newly entered passphrase is
# verified against it, so every blob is guaranteed to stay on the same passphrase.
SHARED_PASSPHRASE=""

# Echo the path of an already-existing blob other than $1 (the one we're writing).
other_existing_blob() {
    for b in "$VPN_BLOB" "$SSH_BLOB" "$ENV_BLOB"; do
        [ "$b" != "$1" ] && [ -f "$b" ] && { echo "$b"; return 0; }
    done
}
# Does the currently-held passphrase actually decrypt $1?
passphrase_unlocks() {
    gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 \
        --decrypt "$1" >/dev/null 2>&1 3<<<"$SHARED_PASSPHRASE"
}

gpg_encrypt() {  # gpg_encrypt OUTFILE   (plaintext arrives on stdin)
    if [ -z "$SHARED_PASSPHRASE" ]; then
        local ref; ref="$(other_existing_blob "$1")"
        while :; do
            # Read from the terminal, not stdin — stdin carries the plaintext pipe.
            read -r -s -p "Passphrase to encrypt your VPN + SSH data: " SHARED_PASSPHRASE </dev/tty; echo
            if [ -z "$SHARED_PASSPHRASE" ]; then
                echo "Passphrase cannot be empty. Try again." >&2; continue
            fi
            if [ -n "$ref" ]; then
                # Must match the passphrase already protecting the other blob.
                passphrase_unlocks "$ref" && break
                echo "That doesn't match the passphrase on $(basename "$ref") — VPN and SSH must share one. Try again." >&2
                SHARED_PASSPHRASE=""
            else
                # First/only blob: confirm to guard against typos.
                read -r -s -p "Confirm passphrase: " _pp_confirm </dev/tty; echo
                [ "$SHARED_PASSPHRASE" = "$_pp_confirm" ] && { unset _pp_confirm; break; }
                echo "Passphrases did not match. Try again." >&2; SHARED_PASSPHRASE=""
            fi
        done
    fi
    gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-fd 3 \
        --symmetric --cipher-algo AES256 --output "$1" 3<<<"$SHARED_PASSPHRASE"
}
gpg_decrypt() {  # gpg_decrypt INFILE    (plaintext written to stdout)
    # Ensure we hold a passphrase that unlocks THIS blob; prompt/re-prompt as needed.
    if [ -z "$SHARED_PASSPHRASE" ] || ! passphrase_unlocks "$1"; then
        while :; do
            # Read from the terminal, not stdin — gpg_decrypt often runs in a pipe.
            read -r -s -p "Passphrase to decrypt your VPN + SSH data: " SHARED_PASSPHRASE </dev/tty; echo
            [ -n "$SHARED_PASSPHRASE" ] && passphrase_unlocks "$1" && break
            echo "Wrong passphrase for $(basename "$1"). Try again." >&2
        done
    fi
    gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 \
        --decrypt "$1" 3<<<"$SHARED_PASSPHRASE"
}

# Prompt once, in the CURRENT shell, for the shared passphrase and verify it
# unlocks $1. Run this before any pipeline/process-substitution decrypt: those
# run gpg_decrypt in a subshell, so a passphrase entered there wouldn't persist.
# Priming it here means the later subshell decrypts inherit it and never re-ask.
prime_passphrase() {  # $1 = a blob the passphrase must unlock
    [ -n "$SHARED_PASSPHRASE" ] && return 0
    while :; do
        read -r -s -p "Passphrase for your VPN + SSH data: " SHARED_PASSPHRASE </dev/tty; echo
        [ -n "$SHARED_PASSPHRASE" ] && passphrase_unlocks "$1" && break
        echo "Wrong passphrase. Try again." >&2
        SHARED_PASSPHRASE=""
    done
}

# True if NetworkManager already has an L2TP VPN connection — lets us detect an
# already-installed VPN without decrypting the blob (so no needless passphrase prompt).
l2tp_vpn_installed() {
    local name type
    while IFS=: read -r name type; do
        [ "$type" = "vpn" ] || continue
        if nmcli -t -f vpn.service-type connection show "$name" 2>/dev/null | grep -q l2tp; then
            return 0
        fi
    done < <(nmcli -t -f NAME,TYPE connection show 2>/dev/null)
    return 1
}

# --- VPN provisioning ---------------------------------------------------------
# ./setup.sh prepare  → if no encrypted VPN config exists yet, offer to create
# one: prompt for VPN details and write an AES256 GPG blob next to this script.
# The plaintext is never written to disk; a stolen USB only ever holds the
# encrypted blob, useless without your passphrase. Safe to re-run: it's a no-op
# once the blob exists. To reconfigure, delete the blob and run prepare again.
vpn_prepare() {
    if [ -f "$VPN_BLOB" ]; then
        echo "VPN config already exists: $VPN_BLOB"
        echo "Nothing to do. To reconfigure, delete it and run: ./setup.sh prepare"
        return 0
    fi
    read -r -p "Configure a VPN connection now? [y/N] " ans
    case "$ans" in
        [Yy]*) ;;
        *) echo "Skipping VPN configuration."; return 0 ;;
    esac
    command -v gpg >/dev/null 2>&1 || { sudo apt update -y && sudo apt install -y gnupg; }
    echo "Enter VPN details (password and PSK are hidden):"
    read -r -p "Connection name [work]: " name; name="${name:-work}"
    read -r -p "Gateway (host/IP):     " gateway
    read -r -p "Username:              " user
    read -r -s -p "Password:             " password; echo
    read -r -s -p "IPsec PSK / secret:   " psk; echo
    read -r -p "IKE proposal (blank=auto): " ike
    read -r -p "ESP proposal (blank=auto): " esp
    [ -n "$gateway" ] && [ -n "$user" ] && [ -n "$password" ] && [ -n "$psk" ] || {
        echo "gateway, username, password and PSK are all required" >&2; exit 1; }
    printf 'VPN_NAME=%s\nVPN_GATEWAY=%s\nVPN_USER=%s\nVPN_PASSWORD=%s\nVPN_PSK=%s\nVPN_IKE=%s\nVPN_ESP=%s\n' \
        "$name" "$gateway" "$user" "$password" "$psk" "$ike" "$esp" \
        | gpg_encrypt "$VPN_BLOB"
    chmod 600 "$VPN_BLOB"
    echo "Wrote $VPN_BLOB — keep it on the USB next to setup.sh. Plaintext was not saved."
}

# --- SSH key provisioning -----------------------------------------------------
# ./setup.sh prepare  → bundle your ~/.ssh/id_rsa keypair into a single AES256
# GPG blob next to this script. The plaintext private key never lands on the USB
# unencrypted; a stolen USB only ever holds the encrypted blob. Safe to re-run:
# it's a no-op once the blob exists. To re-capture, delete the blob and re-run.
# If no keypair exists yet, offer to generate a fresh RSA 4096 one first.
ssh_prepare() {
    if [ -f "$SSH_BLOB" ]; then
        echo "SSH key blob already exists: $SSH_BLOB"
        echo "Nothing to do. To re-capture, delete it and run: ./setup.sh prepare"
        return 0
    fi
    read -r -p "Capture an SSH keypair into an encrypted blob now? [y/N] " ans
    case "$ans" in
        [Yy]*) ;;
        *) echo "Skipping SSH key capture."; return 0 ;;
    esac
    command -v gpg >/dev/null 2>&1 || { sudo apt update -y && sudo apt install -y gnupg; }

    if [ ! -f "$HOME/.ssh/id_rsa" ] || [ ! -f "$HOME/.ssh/id_rsa.pub" ]; then
        echo "No ~/.ssh/id_rsa keypair found."
        read -r -p "Generate a new RSA 4096 keypair now? [y/N] " gen
        case "$gen" in
            [Yy]*)
                mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
                # -N "" → no key passphrase; the keypair's at-rest protection is
                # the AES256 PGP passphrase on the blob, so a second one is redundant.
                ssh-keygen -t rsa -b 4096 -N "" -f "$HOME/.ssh/id_rsa" -C "$(id -un)@$(hostname)"
                ;;
            *) echo "Nothing to capture without a keypair — aborting."; return 1 ;;
        esac
    fi

    # tar both halves of the keypair, then symmetrically encrypt the stream.
    tar -C "$HOME/.ssh" -cf - id_rsa id_rsa.pub \
        | gpg_encrypt "$SSH_BLOB"
    chmod 600 "$SSH_BLOB"
    echo "Wrote $SSH_BLOB — keep it on the USB next to setup.sh. Plaintext key was not copied."
}

# --- .env provisioning --------------------------------------------------------
# ./setup.sh prepare  → encrypt ~/.env into an AES256 GPG blob next to this
# script, using the same shared passphrase as the VPN/SSH blobs. No-op if the
# blob already exists or there's no ~/.env to capture.
env_prepare() {
    if [ -f "$ENV_BLOB" ]; then
        echo ".env blob already exists: $ENV_BLOB"
        echo "Nothing to do. To re-capture, delete it and run: ./setup.sh prepare"
        return 0
    fi
    if [ ! -f "$HOME/.env" ]; then
        echo "No ~/.env to capture — skipping."
        return 0
    fi
    read -r -p "Capture ~/.env into an encrypted blob now? [y/N] " ans
    case "$ans" in
        [Yy]*) ;;
        *) echo "Skipping .env capture."; return 0 ;;
    esac
    command -v gpg >/dev/null 2>&1 || { sudo apt update -y && sudo apt install -y gnupg; }
    gpg_encrypt "$ENV_BLOB" < "$HOME/.env"
    chmod 600 "$ENV_BLOB"
    echo "Wrote $ENV_BLOB — keep it on the USB next to setup.sh. Plaintext was not copied."
}

if [ "${1:-}" = "prepare" ]; then
    vpn_prepare
    ssh_prepare
    env_prepare
    exit 0
fi

echo "Configuring Fish shell and cross-shell devenv environments..."

# 1. Install Fish Shell
sudo apt update -y
sudo apt install -y fish curl wget git ripgrep gnupg unzip xz-utils glab gh gnome-shell-extension-manager wl-clipboard xclip

# 2. Change your default login shell to Fish natively
if [ "$SHELL" != "/usr/bin/fish" ]; then
    echo "Switching default shell to Fish (requires your sudo password)..."
    sudo chsh -s /usr/bin/fish "$USER"
fi

# 2b. Install Claude Code if it's missing
if ! command -v claude &> /dev/null && [ ! -x "$HOME/.local/bin/claude" ]; then
    echo "Claude Code not found — installing..."
    curl -fsSL https://claude.ai/install.sh | bash
else
    echo "Claude Code already installed — skipping."
fi

# -----------------------------------------------------------------------------
# Bash Configurations (~/.bashrc)
# -----------------------------------------------------------------------------
echo "Configuring Bash fallback profile..."
mkdir -p "$HOME/.config"

# Add ~/.local/bin to PATH for Bash (only if not already configured)
if [ -f "$HOME/.bashrc" ] && ! grep -q '.local/bin' "$HOME/.bashrc"; then
    cat << 'EOF' >> "$HOME/.bashrc"

# --- Local bin on PATH ---
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH" ;;
esac
EOF
fi

# Safe, repeatable append for Bash
if [ -f "$HOME/.bashrc" ]; then
    if ! grep -q "direnv hook bash" "$HOME/.bashrc"; then
        cat << 'EOF' >> "$HOME/.bashrc"

# --- Devenv & Direnv Integrations ---
if [ -f "/nix/var/nix/profiles/default/etc/profile.d/nix-profile.sh" ]; then
    . /nix/var/nix/profiles/default/etc/profile.d/nix-profile.sh
fi
eval "$(direnv hook bash)"
EOF
    fi
fi

# Load ~/.env into every interactive Bash session (idempotent). 'set -a' exports
# everything defined while sourcing, so plain KEY=value lines become env vars.
if [ -f "$HOME/.bashrc" ] && ! grep -q "Load ~/.env" "$HOME/.bashrc"; then
    cat << 'EOF' >> "$HOME/.bashrc"

# --- Load ~/.env into the environment ---
if [ -f "$HOME/.env" ]; then
    set -a
    . "$HOME/.env"
    set +a
fi
EOF
fi

# -----------------------------------------------------------------------------
# Fish Configurations (~/.config/fish/config.fish)
# -----------------------------------------------------------------------------
echo "Configuring Fish native profile..."
mkdir -p "$HOME/.config/fish"
touch "$HOME/.config/fish/config.fish"

# Add ~/.local/bin to PATH for Fish (only if not already configured)
if ! grep -q '.local/bin' "$HOME/.config/fish/config.fish"; then
    cat << 'EOF' >> "$HOME/.config/fish/config.fish"

# --- Local bin on PATH ---
if test -d "$HOME/.local/bin"
    fish_add_path "$HOME/.local/bin"
end
EOF
fi

# Idempotent blocks for fish config syntax
if ! grep -q "nix-profile.sh" "$HOME/.config/fish/config.fish"; then
    cat << 'EOF' >> "$HOME/.config/fish/config.fish"

# --- Nix & Devenv Path Initialization ---
# Safely sources the multi-user Nix script using Fish's built-in compatibility mode
if test -f /nix/var/nix/profiles/default/etc/profile.d/nix-profile.sh
    bass source /nix/var/nix/profiles/default/etc/profile.d/nix-profile.sh
end

# Hook direnv seamlessly into Fish
if command -v direnv &> /dev/null
    direnv hook fish | source
end
EOF
fi

# Load ~/.env into every interactive Fish session (idempotent). Prefer bass so the
# parsing (quotes, etc.) matches Bash exactly; fall back to plain KEY=value lines.
if ! grep -q "Load ~/.env" "$HOME/.config/fish/config.fish"; then
    cat << 'EOF' >> "$HOME/.config/fish/config.fish"

# --- Load ~/.env into the environment ---
if test -f "$HOME/.env"
    if type -q bass
        bass set -a ';' source "$HOME/.env" ';' set +a
    else
        for line in (cat "$HOME/.env")
            string match -qr '^\s*(#|$)' -- $line; and continue
            set -l kv (string split -m1 '=' -- $line)
            test (count $kv) -eq 2; or continue
            set -l val (string trim -- $kv[2])
            # strip one layer of matching surrounding single/double quotes
            set val (string replace -r '^(["\'])(.*)\1$' '$2' -- $val)
            set -gx (string trim -- $kv[1]) $val
        end
    end
end
EOF
fi

# -----------------------------------------------------------------------------
# 3. Installing Fish Plugin Support (Fixes POSIX compatibility)
# -----------------------------------------------------------------------------
# Because Nix relies on a Bash script (/nix-profile.sh) to export paths, Fish needs 
# a plugin called 'bass' to read it natively without broken environment variables.
echo "Injecting Fisher (Plugin Manager) and Bass for Nix compatibility..."
fish -c "curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source && fisher install jorgebucaran/fisher"
fish -c "fisher install edc/bass"

# Docker Engine & Docker Compose V2
echo "Setting up Docker Engine & Compose..."
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt update -y
fi
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Ensure user is in the docker group to prevent needing 'sudo' for container execution
if ! groups "$USER" | grep -q "\bdocker\b"; then
    sudo usermod -aG docker "$USER"
    echo "You've been added to the Docker group. You may need to log out and back in for group changes to take effect."
fi

# Lazydocker (Terminal UI for Docker, not packaged in apt)
echo "Installing Lazydocker..."
if ! command -v lazydocker &> /dev/null; then
    curl -fsSL https://raw.githubusercontent.com/jesseduffield/lazydocker/master/scripts/install_update_linux.sh | bash
fi

# L2TP/IPsec VPN support for NetworkManager (GNOME GUI integration)
echo "Installing GNOME L2TP NetworkManager plugin..."
sudo apt install -y network-manager-l2tp network-manager-l2tp-gnome

# Restore VPN + SSH secrets from the encrypted blobs sitting next to this script.
# The blobs may have been copied as root (e.g. sudo cp off the USB), leaving them
# unreadable by the current user. Reclaim ownership so gpg can read them.
for _blob in "$VPN_BLOB" "$SSH_BLOB" "$ENV_BLOB"; do
    if [ -f "$_blob" ] && [ ! -r "$_blob" ]; then
        echo "Fixing ownership of $_blob..."
        sudo chown "$(id -un):$(id -gn)" "$_blob"
        sudo chmod 600 "$_blob"
    fi
done

# Work out what actually needs decrypting BEFORE asking for a passphrase, so a
# machine that's already set up is never prompted at all.
need_vpn=false
if [ -f "$VPN_BLOB" ] && ! l2tp_vpn_installed; then need_vpn=true; fi
need_ssh=false
if [ -f "$SSH_BLOB" ] && { [ ! -f "$HOME/.ssh/id_rsa" ] || [ ! -f "$HOME/.ssh/id_rsa.pub" ]; }; then
    need_ssh=true
fi
need_env=false
if [ -f "$ENV_BLOB" ] && [ ! -f "$HOME/.env" ]; then need_env=true; fi

# Prompt for the one shared passphrase a single time, here in the main shell, so
# the subshell decrypts below (process substitution / pipeline) inherit it.
if [ "$need_vpn" = true ] || [ "$need_ssh" = true ] || [ "$need_env" = true ]; then
    for _b in "$VPN_BLOB" "$SSH_BLOB" "$ENV_BLOB"; do
        if [ -f "$_b" ]; then prime_passphrase "$_b"; break; fi
    done
fi

# --- VPN ---
if [ "$need_vpn" = true ]; then
    echo "Configuring VPN connection from encrypted config..."
    VPN_NAME=""; VPN_GATEWAY=""; VPN_USER=""; VPN_PASSWORD=""; VPN_PSK=""; VPN_IKE=""; VPN_ESP=""
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        key="${line%%=*}"; val="${line#*=}"
        case "$key" in
            VPN_NAME)     VPN_NAME="$val" ;;
            VPN_GATEWAY)  VPN_GATEWAY="$val" ;;
            VPN_USER)     VPN_USER="$val" ;;
            VPN_PASSWORD) VPN_PASSWORD="$val" ;;
            VPN_PSK)      VPN_PSK="$val" ;;
            VPN_IKE)      VPN_IKE="$val" ;;
            VPN_ESP)      VPN_ESP="$val" ;;
        esac
    done < <(gpg_decrypt "$VPN_BLOB")
    VPN_NAME="${VPN_NAME:-work}"

    if [ -z "$VPN_GATEWAY" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ] || [ -z "$VPN_PSK" ]; then
        echo "Decrypted VPN config is incomplete (wrong passphrase?) — skipping VPN setup." >&2
    else
        uuid="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"
        ike_line=""; esp_line=""
        [ -n "$VPN_IKE" ] && ike_line="ipsec-ike=$VPN_IKE"
        [ -n "$VPN_ESP" ] && esp_line="ipsec-esp=$VPN_ESP"
        keyfile="/etc/NetworkManager/system-connections/${VPN_NAME}.nmconnection"
        # password-flags=0 stores the secret in the root-only 0600 keyfile, so the
        # tunnel comes up without a desktop secret-agent prompt.
        sudo tee "$keyfile" >/dev/null <<EOF
[connection]
id=${VPN_NAME}
uuid=${uuid}
type=vpn
autoconnect=false

[vpn]
service-type=org.freedesktop.NetworkManager.l2tp
gateway=${VPN_GATEWAY}
user=${VPN_USER}
password-flags=0
ipsec-enabled=yes
ipsec-psk=${VPN_PSK}
${ike_line}
${esp_line}

[vpn-secrets]
password=${VPN_PASSWORD}

[ipv4]
method=auto

[ipv6]
method=auto
EOF
        sudo chown root:root "$keyfile"
        sudo chmod 600 "$keyfile"
        sudo nmcli connection reload 2>/dev/null || true
        echo "VPN '$VPN_NAME' installed.  Connect: nmcli connection up '$VPN_NAME'"
    fi
    unset VPN_PASSWORD VPN_PSK
elif [ -f "$VPN_BLOB" ]; then
    echo "An L2TP VPN is already configured — skipping VPN setup."
else
    echo "No vpn.conf.gpg next to setup.sh — skipping VPN setup."
    echo "Create one first with:  ./setup.sh prepare"
fi

# --- SSH keys --- (only the halves missing from ~/.ssh are restored)
if [ "$need_ssh" = true ]; then
    echo "Restoring SSH keypair from encrypted blob..."
    mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
    extract=""
    [ ! -f "$HOME/.ssh/id_rsa" ]     && extract="$extract id_rsa"
    [ ! -f "$HOME/.ssh/id_rsa.pub" ] && extract="$extract id_rsa.pub"
    if gpg_decrypt "$SSH_BLOB" | tar -C "$HOME/.ssh" -xf - $extract; then
        [ -f "$HOME/.ssh/id_rsa" ]     && chmod 600 "$HOME/.ssh/id_rsa"
        [ -f "$HOME/.ssh/id_rsa.pub" ] && chmod 644 "$HOME/.ssh/id_rsa.pub"
        echo "SSH keypair restored to ~/.ssh."
    else
        echo "Failed to decrypt/extract SSH keys (wrong passphrase?) — skipping." >&2
    fi
elif [ -f "$SSH_BLOB" ]; then
    echo "SSH keypair already present in ~/.ssh — leaving it untouched."
else
    echo "No ssh.keys.tar.gpg next to setup.sh — skipping SSH key restore."
    echo "Create one first with:  ./setup.sh prepare"
fi

# --- .env file --- (restored only when missing; decrypt to a temp then move so a
# wrong passphrase never leaves a partial ~/.env behind)
if [ "$need_env" = true ]; then
    echo "Restoring ~/.env from encrypted blob..."
    tmp_env="$(mktemp)"
    if gpg_decrypt "$ENV_BLOB" > "$tmp_env"; then
        mv "$tmp_env" "$HOME/.env"
        chmod 600 "$HOME/.env"
        echo "~/.env restored."
    else
        rm -f "$tmp_env"
        echo "Failed to decrypt ~/.env (wrong passphrase?) — skipping." >&2
    fi
elif [ -f "$ENV_BLOB" ]; then
    echo "~/.env already present — leaving it untouched."
else
    echo "No env.gpg next to setup.sh — skipping .env restore."
fi

# -----------------------------------------------------------------------------
# 3. Editors & IDE Ecosystems
# -----------------------------------------------------------------------------
# Visual Studio Code
echo "Syncing Visual Studio Code..."
if ! command -v code &> /dev/null; then
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
    sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
    sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
    rm -f packages.microsoft.gpg
    sudo apt update -y
fi
sudo apt install -y code

# -----------------------------------------------------------------------------
# Node.js (latest "Current" release, installed globally under /usr/local)
# -----------------------------------------------------------------------------
# Pulls whatever nodejs.org currently publishes as "latest" rather than pinning
# a major, so re-running the script tracks new releases. The official prebuilt
# tarball is extracted straight into /usr/local (node/npm/npx land in
# /usr/local/bin, modules in /usr/local/lib) — a system-wide, global install.
echo "Installing the latest Node.js..."
case "$(dpkg --print-architecture)" in
    amd64) node_arch="linux-x64" ;;
    arm64) node_arch="linux-arm64" ;;
    armhf) node_arch="linux-armv7l" ;;
    *) echo "No Node.js binary for $(dpkg --print-architecture) — skipping." >&2; node_arch="" ;;
esac
if [ -n "$node_arch" ]; then
    node_base="https://nodejs.org/dist/latest"
    # Read the checksum manifest to discover the exact latest filename + version.
    node_tarball="$(curl -fsSL "$node_base/SHASUMS256.txt" \
        | grep -o "node-v[0-9.]*-${node_arch}\.tar\.xz" | head -n1)"
    if [ -z "$node_tarball" ]; then
        echo "Couldn't determine the latest Node.js release — skipping." >&2
    else
        node_ver="${node_tarball#node-}"; node_ver="${node_ver%%-*}"
        if [ "$(node -v 2>/dev/null)" = "$node_ver" ]; then
            echo "Node.js $node_ver already installed — skipping."
        else
            echo "Installing Node.js $node_ver..."
            tmp_node="$(mktemp --suffix=.tar.xz)"
            wget -qO "$tmp_node" "$node_base/$node_tarball"
            # --strip-components=1 drops the versioned top-level dir so files
            # merge cleanly into /usr/local across upgrades.
            sudo tar -xJf "$tmp_node" -C /usr/local --strip-components=1 \
                --no-same-owner --exclude='*.md' --exclude='LICENSE'
            rm -f "$tmp_node"
            echo "Node.js $(/usr/local/bin/node -v) / npm $(/usr/local/bin/npm -v) installed."
        fi
    fi
fi

# Neovim (Latest Stable Binary AppImage deployment)
# Neovim dropped the generic nvim.appimage asset; assets are now arch-specific.
echo "Fetching Latest Neovim..."
case "$(dpkg --print-architecture)" in
    amd64) nvim_asset="nvim-linux-x86_64.appimage" ;;
    arm64) nvim_asset="nvim-linux-arm64.appimage" ;;
    *) echo "No Neovim AppImage for $(dpkg --print-architecture) — skipping." >&2; nvim_asset="" ;;
esac
if [ -n "$nvim_asset" ]; then
    sudo wget -O /usr/local/bin/nvim \
        "https://github.com/neovim/neovim/releases/latest/download/$nvim_asset"
    sudo chmod +x /usr/local/bin/nvim
fi

# NvChad (Idempotent Starter Setup)
echo "Layering NvChad config structure..."
if [ ! -d "$HOME/.config/nvim" ]; then
    # Clone the official starter repository directly to the standard Neovim destination
    git clone https://github.com/NvChad/starter "$HOME/.config/nvim"
else
    echo "Neovim config directory already exists. Pulling latest structural updates..."
    # If running script down the line, gracefully refresh git tracking states safely
    if [ -d "$HOME/.config/nvim/.git" ]; then
        cd "$HOME/.config/nvim" && git pull && cd - > /dev/null
    fi
fi

# Alias vim → nvim for both shells (idempotent)
echo "Aliasing vim → nvim..."
if [ -f "$HOME/.bashrc" ] && ! grep -q "alias vim" "$HOME/.bashrc"; then
    printf "\nalias vim='nvim'\n" >> "$HOME/.bashrc"
fi
if [ -f "$HOME/.config/fish/config.fish" ] && ! grep -q "alias vim" "$HOME/.config/fish/config.fish"; then
    printf "\nalias vim 'nvim'\n" >> "$HOME/.config/fish/config.fish"
fi

# Alias clip → wl-copy on Wayland, "xclip -sel clip" otherwise (idempotent).
# Resolved at shell startup so the same config works in either session type.
echo "Aliasing clip → clipboard copier..."
if [ -f "$HOME/.bashrc" ] && ! grep -q "alias clip" "$HOME/.bashrc"; then
    cat << 'EOF' >> "$HOME/.bashrc"

# --- clip → clipboard copier (Wayland: wl-copy, X11: xclip) ---
if [ -n "$WAYLAND_DISPLAY" ]; then
    alias clip='wl-copy'
else
    alias clip='xclip -sel clip'
fi
EOF
fi
if [ -f "$HOME/.config/fish/config.fish" ] && ! grep -q "alias clip" "$HOME/.config/fish/config.fish"; then
    cat << 'EOF' >> "$HOME/.config/fish/config.fish"

# --- clip → clipboard copier (Wayland: wl-copy, X11: xclip) ---
if set -q WAYLAND_DISPLAY
    alias clip 'wl-copy'
else
    alias clip 'xclip -sel clip'
end
EOF
fi

# -----------------------------------------------------------------------------
# Desktop keyboard shortcuts (GNOME custom keybindings)
#   Super+Enter → terminal,  Super+B → browser,  Super+S → settings
#   Super+Q     → close the focused window (built-in WM action)
# -----------------------------------------------------------------------------
echo "Configuring GNOME keyboard shortcuts..."
if command -v gsettings >/dev/null 2>&1 \
   && gsettings list-schemas 2>/dev/null | grep -q '^org.gnome.settings-daemon.plugins.media-keys$'; then

    # Resolve a terminal command (Ptyxis is the default on current Ubuntu/GNOME).
    if   command -v ptyxis            >/dev/null 2>&1; then term_cmd="ptyxis --new-window"
    elif command -v gnome-terminal    >/dev/null 2>&1; then term_cmd="gnome-terminal"
    elif command -v x-terminal-emulator >/dev/null 2>&1; then term_cmd="x-terminal-emulator"
    else term_cmd="xterm"; fi

    # Resolve a browser command: a concrete installed browser, else the XDG
    # default resolved at keypress time, else a last-resort xdg-open.
    browser_cmd=""
    for b in firefox google-chrome-stable google-chrome chromium-browser chromium brave-browser; do
        if command -v "$b" >/dev/null 2>&1; then browser_cmd="$b"; break; fi
    done
    if [ -z "$browser_cmd" ]; then
        if command -v xdg-settings >/dev/null 2>&1 && command -v gtk-launch >/dev/null 2>&1; then
            browser_cmd="sh -c 'gtk-launch \$(xdg-settings get default-web-browser)'"
        else
            browser_cmd="xdg-open https://"
        fi
    fi

    settings_cmd="gnome-control-center"

    mk="org.gnome.settings-daemon.plugins.media-keys"
    cks="org.gnome.settings-daemon.plugins.media-keys.custom-keybinding"
    base="/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings"

    # Stable slot paths (descriptive, not customN) so re-running just overwrites
    # our own shortcuts and never disturbs ones the user created.
    p_term="$base/setup-terminal/"
    p_brow="$base/setup-browser/"
    p_set="$base/setup-settings/"

    declare -A kb_name kb_bind kb_cmd
    kb_name["$p_term"]="Open Terminal"; kb_bind["$p_term"]="<Super>Return"; kb_cmd["$p_term"]="$term_cmd"
    kb_name["$p_brow"]="Open Browser";  kb_bind["$p_brow"]="<Super>b";      kb_cmd["$p_brow"]="$browser_cmd"
    kb_name["$p_set"]="Open Settings";  kb_bind["$p_set"]="<Super>s";       kb_cmd["$p_set"]="$settings_cmd"

    for p in "$p_term" "$p_brow" "$p_set"; do
        gsettings set "$cks:$p" name    "${kb_name[$p]}"
        gsettings set "$cks:$p" command "${kb_cmd[$p]}"
        gsettings set "$cks:$p" binding "${kb_bind[$p]}"
    done

    # Merge our slot paths into the custom-keybindings list, preserving any the
    # user already had and avoiding duplicates on re-run.
    mapfile -t existing < <(gsettings get "$mk" custom-keybindings 2>/dev/null | grep -oE "'[^']*'" | tr -d "'")
    declare -A seen=()
    merged=()
    for p in "${existing[@]}" "$p_term" "$p_brow" "$p_set"; do
        [ -n "$p" ] || continue
        if [ -z "${seen[$p]:-}" ]; then seen["$p"]=1; merged+=("$p"); fi
    done
    list="["; sep=""
    for p in "${merged[@]}"; do list="$list$sep'$p'"; sep=", "; done
    list="$list]"
    gsettings set "$mk" custom-keybindings "$list"

    # Super+Q → close the focused window. This is a built-in window-manager
    # action (not a command to run), so it lives in the wm.keybindings schema
    # rather than the custom-keybindings list above.
    if gsettings list-schemas 2>/dev/null | grep -q '^org.gnome.desktop.wm.keybindings$'; then
        gsettings set org.gnome.desktop.wm.keybindings close "['<Super>q']"
        echo "Shortcuts set: Super+Enter → terminal ($term_cmd), Super+B → browser, Super+S → settings, Super+Q → close window."
    else
        echo "Shortcuts set: Super+Enter → terminal ($term_cmd), Super+B → browser, Super+S → settings."
        echo "GNOME wm.keybindings schema not available — skipping Super+Q (close window)." >&2
    fi
else
    echo "GNOME media-keys schema not available — skipping keyboard shortcuts." >&2
fi

echo "Configuration complete! Close your terminal or log out/in to drop directly into your fresh Fish environment."
