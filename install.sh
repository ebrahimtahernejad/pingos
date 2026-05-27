#!/usr/bin/env bash
#
# pingos · install wizard
#
#   curl -fsSL https://github.com/EbrahimTahernejad/pingos/releases/latest/download/install.sh | sudo bash
#
# What it does:
#   - confirms you're on linux with systemd + root
#   - lets you pick server or client
#   - walks you through settings (password, fec, compression, ports)
#   - downloads the right binary from the latest GitHub release
#   - generates /etc/pingos/<role>.toml from your answers
#   - drops a systemd unit at /etc/systemd/system/pingos.service
#   - enables + starts the service
#   - prints next steps
#
# Env overrides (skip prompts):
#   PINGOS_ROLE=server|client
#   PINGOS_VERSION=v0.1.0     (default: latest)
#   PINGOS_PASSWORD=...
#   PINGOS_COMPRESSION=none|lz4
#   PINGOS_FEC=8:2
#   PINGOS_BIND=0.0.0.0           # server-only
#   PINGOS_LISTEN=0.0.0.0:4455    # client-only
#   PINGOS_SERVER=tunnel.example  # client-only
#   PINGOS_TARGET=10.0.0.1:80     # client-only
#   PINGOS_NONINTERACTIVE=1       # die if any prompt needed
#   PINGOS_DRY_RUN=1              # show what would happen, don't touch the system

set -euo pipefail

REPO="EbrahimTahernejad/pingos"

# ──────────────────────── style ────────────────────────────────────────────

# Auto-disable colors when not on a TTY.
if [[ -t 1 ]] || [[ "${FORCE_COLOR:-}" == 1 ]]; then
    C_RESET=$'\e[0m'
    C_DIM=$'\e[2m'
    C_BOLD=$'\e[1m'

    # palette — neon on dark, swagger.
    C_CYAN=$'\e[38;5;51m'
    C_PINK=$'\e[38;5;201m'
    C_GREEN=$'\e[38;5;82m'
    C_GOLD=$'\e[38;5;220m'
    C_RED=$'\e[38;5;196m'
    C_GRAY=$'\e[38;5;245m'
    C_PURPLE=$'\e[38;5;141m'
else
    C_RESET="" C_DIM="" C_BOLD=""
    C_CYAN="" C_PINK="" C_GREEN="" C_GOLD="" C_RED="" C_GRAY="" C_PURPLE=""
fi

say()   { printf '%s\n' "$*"; }
info()  { printf '  %s%s%s %s\n' "$C_CYAN"  "·"  "$C_RESET" "$*"; }
ok()    { printf '  %s%s%s %s\n' "$C_GREEN" "✓"  "$C_RESET" "$*"; }
warn()  { printf '  %s%s%s %s\n' "$C_GOLD"  "!"  "$C_RESET" "$*"; }
fail()  { printf '  %s%s%s %s\n' "$C_RED"   "✗"  "$C_RESET" "$*" >&2; }

die()   { fail "$*"; exit 1; }

banner() {
    cat <<EOF

${C_PINK}    ╭──────────────────────────────────────────────────────────╮${C_RESET}
${C_PINK}    │${C_RESET}                                                          ${C_PINK}│${C_RESET}
${C_PINK}    │${C_RESET}   ${C_BOLD}${C_CYAN}pingos${C_RESET} ${C_GRAY}·${C_RESET} install wizard                              ${C_PINK}│${C_RESET}
${C_PINK}    │${C_RESET}   ${C_GRAY}tcp-over-icmp tunnel${C_RESET}                                   ${C_PINK}│${C_RESET}
${C_PINK}    │${C_RESET}                                                          ${C_PINK}│${C_RESET}
${C_PINK}    ╰──────────────────────────────────────────────────────────╯${C_RESET}

EOF
}

section() {
    printf "\n${C_BOLD}${C_PURPLE}▸${C_RESET}  ${C_BOLD}%s${C_RESET}\n\n" "$*"
}

# Escape a value for use inside a TOML basic-string ("...").
toml_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# Spinner that wraps a long-running command.
#   run "label" cmd args...
run() {
    local label="$1"; shift
    if [[ "${PINGOS_DRY_RUN:-}" == 1 ]]; then
        info "[dry-run] $label: $*"
        return 0
    fi
    local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0 pid
    "$@" >/tmp/pingos-install.log 2>&1 &
    pid=$!
    if [[ -t 1 ]]; then tput civis 2>/dev/null || true; fi
    while kill -0 "$pid" 2>/dev/null; do
        local ch="${frames:$((i % ${#frames})):1}"
        printf '\r  %s%s%s %s' "$C_CYAN" "$ch" "$C_RESET" "$label" >&2
        i=$((i+1))
        sleep 0.08 2>/dev/null || true
    done
    if [[ -t 1 ]]; then tput cnorm 2>/dev/null || true; fi
    if wait "$pid"; then
        printf '\r  %s%s%s %s\n' "$C_GREEN" "✓" "$C_RESET" "$label"
    else
        printf '\r  %s%s%s %s\n' "$C_RED" "✗" "$C_RESET" "$label" >&2
        say
        say "${C_RED}${C_BOLD}command output:${C_RESET}"
        sed 's/^/      /' /tmp/pingos-install.log >&2
        return 1
    fi
}

# ───────────────────── input (reads /dev/tty so curl|bash works) ──────────

is_interactive() { [[ -e /dev/tty ]]; }

ask() {
    # ask "Prompt" "default" → echoes user's response (or default)
    local q="$1" def="${2:-}" line
    if [[ "${PINGOS_NONINTERACTIVE:-}" == 1 ]]; then
        if [[ -z "$def" ]]; then die "non-interactive: missing value for '$q'"; fi
        printf '%s\n' "$def"
        return
    fi
    if ! is_interactive; then
        if [[ -z "$def" ]]; then die "no /dev/tty for prompt '$q' and no default"; fi
        printf '%s\n' "$def"
        return
    fi
    if [[ -n "$def" ]]; then
        printf '  %s%s%s %s %s[%s]%s ' "$C_PINK" "›" "$C_RESET" "$q" "$C_GRAY" "$def" "$C_RESET" > /dev/tty
    else
        printf '  %s%s%s %s ' "$C_PINK" "›" "$C_RESET" "$q" > /dev/tty
    fi
    IFS= read -r line < /dev/tty || true
    printf '%s\n' "${line:-$def}"
}

confirm() {
    # confirm "Question" "Y|n"  → returns 0 if yes
    local q="$1" def="${2:-Y}" ans
    if [[ "${PINGOS_NONINTERACTIVE:-}" == 1 ]] || ! is_interactive; then
        [[ "${def^^}" == Y* ]]
        return
    fi
    local hint
    if [[ "${def^^}" == Y* ]]; then hint="${C_BOLD}Y${C_RESET}/n"; else hint="y/${C_BOLD}N${C_RESET}"; fi
    printf '  %s%s%s %s %s[%b]%s ' "$C_PINK" "›" "$C_RESET" "$q" "$C_GRAY" "$hint" "$C_RESET" > /dev/tty
    IFS= read -r ans < /dev/tty || true
    ans="${ans:-$def}"
    [[ "${ans^^}" == Y* ]]
}

choose() {
    # choose "label" "opt1" "opt2" ... → echoes index (1-based) of chosen
    local label="$1"; shift
    local opts=("$@") i
    printf '  %s%s%s %s\n\n' "$C_PINK" "›" "$C_RESET" "$label" > /dev/tty
    for i in "${!opts[@]}"; do
        printf '       %s%d%s  %s\n' "$C_GOLD" "$((i+1))" "$C_RESET" "${opts[$i]}" > /dev/tty
    done
    say > /dev/tty
    local pick
    while :; do
        printf '  %s%s%s pick a number ' "$C_PINK" "›" "$C_RESET" > /dev/tty
        IFS= read -r pick < /dev/tty || true
        if [[ "$pick" =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= ${#opts[@]} )); then
            printf '%s\n' "$pick"
            return
        fi
        printf '       %s%s%s try again\n' "$C_RED" "✗" "$C_RESET" > /dev/tty
    done
}

# ───────────────────── system checks ──────────────────────────────────────

require_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "needs root."
        say  "   try: ${C_BOLD}curl -fsSL https://github.com/$REPO/releases/latest/download/install.sh | sudo bash${C_RESET}"
        exit 1
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) die "unsupported architecture: $(uname -m) — only x86_64 and aarch64 right now" ;;
    esac
}

system_check() {
    section "system check"
    [[ "$(uname -s)" == "Linux" ]] || die "linux only — found $(uname -s)"
    ok "linux $(uname -r)"

    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemd not detected. this installer is systemd-only."
    fi
    local sv
    sv=$(systemctl --version 2>/dev/null | head -1 | awk '{print $2}')
    ok "systemd $sv"

    [[ $EUID -eq 0 ]] || die "running as uid $EUID — need root"
    ok "running as root"

    ARCH=$(detect_arch)
    ok "arch: $ARCH"

    if ! command -v curl >/dev/null 2>&1; then die "missing 'curl'"; fi
    ok "curl present"
}

# ───────────────────── role + settings wizard ─────────────────────────────

wizard_role() {
    section "what we installing?"
    if [[ -n "${PINGOS_ROLE:-}" ]]; then
        ROLE="$PINGOS_ROLE"
        info "role from env: ${C_BOLD}$ROLE${C_RESET}"
        return
    fi
    local pick
    pick=$(choose "pick a side" \
        "server  ${C_GRAY}— runs on your VPS, terminates ICMP tunnels${C_RESET}" \
        "client  ${C_GRAY}— runs anywhere, opens local TCP that tunnels over ICMP${C_RESET}")
    case "$pick" in
        1) ROLE="server" ;;
        2) ROLE="client" ;;
    esac
}

random_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 24 2>/dev/null | tr -d '/+=' | head -c 32
    else
        tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32
    fi
}

wizard_settings() {
    section "settings"

    # password
    if [[ -n "${PINGOS_PASSWORD:-}" ]]; then
        PASSWORD="$PINGOS_PASSWORD"
        ok "password from env"
    else
        local def
        def=$(random_password)
        PASSWORD=$(ask "password (used for ChaCha20-Poly1305; both sides must match)" "$def")
    fi

    # compression
    if [[ -n "${PINGOS_COMPRESSION:-}" ]]; then
        COMPRESSION="$PINGOS_COMPRESSION"
        ok "compression from env: $COMPRESSION"
    else
        if confirm "compression (lz4)? trades a bit of cpu for tighter packets" "Y"; then
            COMPRESSION=lz4
        else
            COMPRESSION=none
        fi
    fi

    # fec
    if [[ -n "${PINGOS_FEC:-}" ]]; then
        FEC="$PINGOS_FEC"
        ok "fec from env: $FEC"
    else
        if confirm "FEC? (reed-solomon, helps with packet loss)" "Y"; then
            FEC=$(ask "  group size N:K (data:parity)" "8:2")
        else
            FEC="0:0"
        fi
    fi

    # role-specific
    if [[ "$ROLE" == "server" ]]; then
        if [[ -n "${PINGOS_BIND:-}" ]]; then
            BIND="$PINGOS_BIND"; ok "bind from env: $BIND"
        else
            BIND=$(ask "bind address (which interface listens for ICMP)" "0.0.0.0")
        fi
    else
        if [[ -n "${PINGOS_LISTEN:-}" ]]; then
            LISTEN="$PINGOS_LISTEN"; ok "listen from env: $LISTEN"
        else
            LISTEN=$(ask "local TCP listen address" "127.0.0.1:4455")
        fi
        if [[ -n "${PINGOS_SERVER:-}" ]]; then
            SERVER="$PINGOS_SERVER"; ok "server from env: $SERVER"
        else
            SERVER=$(ask "server hostname or IP (where the pingos server lives)" "")
            [[ -n "$SERVER" ]] || die "server is required"
        fi
        if [[ -n "${PINGOS_TARGET:-}" ]]; then
            TARGET="$PINGOS_TARGET"; ok "target from env: $TARGET"
        else
            TARGET=$(ask "target host:port (where server should forward to)" "")
            [[ -n "$TARGET" ]] || die "target is required"
        fi
    fi
}

# ───────────────────── download + install ─────────────────────────────────

resolve_release_url() {
    local version="${PINGOS_VERSION:-latest}"
    if [[ "$version" == "latest" ]]; then
        echo "https://github.com/$REPO/releases/latest/download/pingos-linux-$ARCH"
    else
        echo "https://github.com/$REPO/releases/download/$version/pingos-linux-$ARCH"
    fi
}

download_binary() {
    section "fetching binary"
    local url tmp_bin
    url=$(resolve_release_url)
    info "url: ${C_DIM}$url${C_RESET}"
    tmp_bin=$(mktemp)
    if [[ "${PINGOS_DRY_RUN:-}" == 1 ]]; then
        ok "(dry-run) would download → /usr/local/bin/pingos"
        rm -f "$tmp_bin"
        return 0
    fi
    if ! run "downloading pingos binary" curl -fL -o "$tmp_bin" "$url"; then
        say
        warn "couldn't fetch binary."
        warn "either the release doesn't exist yet, or your network is wonky."
        say  "       try setting PINGOS_VERSION=vX.Y.Z, or push a Cargo.toml version bump to main"
        say  "       to trigger the release workflow."
        rm -f "$tmp_bin"
        exit 1
    fi
    chmod +x "$tmp_bin"
    if [[ ! -s "$tmp_bin" ]]; then die "downloaded binary is empty"; fi
    # sanity: file is an ELF binary
    if [[ "$(head -c4 "$tmp_bin" | od -c 2>/dev/null | head -1 | awk '{$1=""; print $0}')" != *"E"*"L"*"F"* ]]; then
        warn "downloaded file doesn't look like an ELF binary; installing anyway"
    fi
    install -m 0755 "$tmp_bin" /usr/local/bin/pingos
    rm -f "$tmp_bin"
    ok "installed → /usr/local/bin/pingos"
    /usr/local/bin/pingos --version 2>/dev/null | sed 's/^/    /' || true
}

# ───────────────────── config + unit ──────────────────────────────────────

write_config() {
    section "writing config"
    mkdir -p /etc/pingos
    chmod 0755 /etc/pingos
    local path="/etc/pingos/${ROLE}.toml"

    if [[ -f "$path" ]] && ! confirm "overwrite existing $path?" "Y"; then
        warn "kept existing $path"
        return
    fi

    local pw_esc; pw_esc=$(toml_escape "$PASSWORD")
    local content
    if [[ "$ROLE" == "server" ]]; then
        content=$(cat <<EOF
# pingos server config — managed by installer, edit and \`systemctl restart pingos\` to apply.
verbose     = false
password    = "$pw_esc"
compression = "$COMPRESSION"
fec         = "$FEC"

[server]
bind              = "$(toml_escape "$BIND")"
dial_timeout_ms   = 5000
idle_timeout_secs = 60
EOF
)
    else
        content=$(cat <<EOF
# pingos client config — managed by installer, edit and \`systemctl restart pingos\` to apply.
verbose     = false
password    = "$pw_esc"
compression = "$COMPRESSION"
fec         = "$FEC"

[client]
listen            = "$(toml_escape "$LISTEN")"
server            = "$(toml_escape "$SERVER")"
target            = "$(toml_escape "$TARGET")"
idle_timeout_secs = 60
EOF
)
    fi

    if [[ "${PINGOS_DRY_RUN:-}" == 1 ]]; then
        info "(dry-run) would write $path:"
        echo "$content" | sed 's/^/    /'
        return
    fi
    umask 077
    printf '%s\n' "$content" > "$path"
    chmod 0600 "$path"
    ok "wrote $path (mode 600 — contains your password)"
}

write_unit() {
    section "writing systemd unit"
    local unit=/etc/systemd/system/pingos.service
    local content
    content=$(cat <<EOF
[Unit]
Description=pingos · tcp-over-icmp tunnel ($ROLE)
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pingos $ROLE --config /etc/pingos/${ROLE}.toml
Restart=on-failure
RestartSec=3

# Hardening (we still run as root for ICMP raw socket).
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/log
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
)
    if [[ "${PINGOS_DRY_RUN:-}" == 1 ]]; then
        info "(dry-run) would write $unit:"
        echo "$content" | sed 's/^/    /'
        return
    fi
    printf '%s\n' "$content" > "$unit"
    chmod 0644 "$unit"
    ok "wrote $unit"
}

enable_and_start() {
    section "starting service"
    if [[ "${PINGOS_DRY_RUN:-}" == 1 ]]; then
        info "(dry-run) would: systemctl daemon-reload"
        info "(dry-run) would: systemctl enable --now pingos"
        return
    fi
    run "systemctl daemon-reload" systemctl daemon-reload
    run "enable + start pingos.service" systemctl enable --now pingos.service
    sleep 1
    if systemctl is-active --quiet pingos.service; then
        ok "pingos.service is ${C_GREEN}${C_BOLD}active${C_RESET}"
    else
        warn "pingos.service is not active — investigate with journalctl"
    fi
}

# ───────────────────── summary ─────────────────────────────────────────────

final_summary() {
    say
    say  "${C_GREEN}${C_BOLD}    ╭──────────────────────────────────────────────────────────╮${C_RESET}"
    say  "${C_GREEN}${C_BOLD}    │${C_RESET}                                                          ${C_GREEN}${C_BOLD}│${C_RESET}"
    say  "${C_GREEN}${C_BOLD}    │${C_RESET}   ${C_BOLD}we live.${C_RESET}                                              ${C_GREEN}${C_BOLD}│${C_RESET}"
    say  "${C_GREEN}${C_BOLD}    │${C_RESET}                                                          ${C_GREEN}${C_BOLD}│${C_RESET}"
    say  "${C_GREEN}${C_BOLD}    ╰──────────────────────────────────────────────────────────╯${C_RESET}"
    say
    say  "  ${C_BOLD}role${C_RESET}        $ROLE"
    say  "  ${C_BOLD}binary${C_RESET}      /usr/local/bin/pingos"
    say  "  ${C_BOLD}config${C_RESET}      /etc/pingos/${ROLE}.toml"
    say  "  ${C_BOLD}unit${C_RESET}        /etc/systemd/system/pingos.service"
    say
    if [[ "$ROLE" == "server" ]]; then
        say  "  ${C_GRAY}point your client at this host:${C_RESET}"
        say  "    ${C_BOLD}pingos client -s $(hostname -I | awk '{print $1}') -l 127.0.0.1:4455 -t YOUR_TARGET:PORT -p '$PASSWORD'${C_RESET}"
        say
        say  "  ${C_GRAY}if outbound ping replies are dropped, also disable the kernel's ping responder:${C_RESET}"
        say  "    ${C_DIM}echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all${C_RESET}"
    else
        say  "  ${C_GRAY}local TCP listener is at: ${C_BOLD}$LISTEN${C_RESET}"
        say  "  ${C_GRAY}tunneled traffic lands at: ${C_BOLD}$TARGET${C_RESET}"
    fi
    say
    say  "  ${C_GRAY}live logs:${C_RESET}     ${C_BOLD}journalctl -u pingos -f${C_RESET}"
    say  "  ${C_GRAY}status:${C_RESET}        ${C_BOLD}systemctl status pingos${C_RESET}"
    say  "  ${C_GRAY}restart:${C_RESET}       ${C_BOLD}systemctl restart pingos${C_RESET}"
    say  "  ${C_GRAY}edit config:${C_RESET}   ${C_BOLD}\$EDITOR /etc/pingos/${ROLE}.toml${C_RESET}"
    say
    say  "${C_GRAY}  password printed once below. save it. both sides need it to match.${C_RESET}"
    say  "  ${C_PINK}${C_BOLD}password:${C_RESET}   ${C_BOLD}$PASSWORD${C_RESET}"
    say
}

# ───────────────────── main ────────────────────────────────────────────────

main() {
    banner
    require_root
    system_check
    wizard_role
    wizard_settings
    download_binary
    write_config
    write_unit
    enable_and_start
    final_summary
}

main "$@"
