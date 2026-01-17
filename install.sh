#!/usr/bin/env bash
set -euo pipefail

# gwshell installer
# Installs:
#   /usr/local/sbin/gwshell
#   /usr/local/sbin/gwctx-shell
#
# Usage (remote):
#   curl -fsSL https://your-host/install-gwshell.sh | sudo bash
#
# Usage (local):
#   sudo bash install-gwshell.sh

DEST_DIR="/usr/local/sbin"
GWSHELL_PATH="${DEST_DIR}/gwshell"
GWCTX_PATH="${DEST_DIR}/gwctx-shell"

warn() { echo "WARN: $*" >&2; }
info() { echo "INFO: $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "must run as root (use sudo)"
  fi
}

check_deps() {
  # hard deps
  local missing=0
  for c in ip iptables systemd-run awk grep shuf tee tr head mkdir rmdir env bash; do
    if ! command -v "$c" >/dev/null 2>&1; then
      warn "missing dependency: $c"
      missing=1
    fi
  done

  # soft deps (optional)
  if ! command -v curl >/dev/null 2>&1; then
    warn "optional dependency missing: curl (External IP probe will show '(unavailable)')"
  fi

  # check cgroup v2
  if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
    warn "cgroup v2 not detected at /sys/fs/cgroup/cgroup.controllers"
    warn "This tool requires cgroup v2 (unified hierarchy)."
    missing=1
  fi

  # check systemd is PID 1 (practical)
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found (systemd likely missing); gwshell relies on systemd-run"
    missing=1
  else
    if [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" != "systemd" ]]; then
      warn "PID 1 is not systemd; systemd-run may not work in this environment"
    fi
  fi

  if [[ $missing -ne 0 ]]; then
    warn "One or more required dependencies are missing. Installation will continue, but gwshell may not work."
  fi
}

install_files() {
  mkdir -p "${DEST_DIR}"

  info "Writing ${GWCTX_PATH}"
  cat >"${GWCTX_PATH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

GWCTX_IFACE="${GWCTX_IFACE:?}"
GWCTX_GW="${GWCTX_GW:?}"
MARK_HEX="${MARK_HEX:?}"
TABLE_ID="${TABLE_ID:?}"
RULE_PRIO="${RULE_PRIO:?}"
GWCTX_LOG="${GWCTX_LOG:-/run/gwshell-${TABLE_ID}.log}"

exec > >(tee -a "${GWCTX_LOG}") 2>&1
log() { printf '%s\n' "$*"; }

IFACE_CIDR="$(
  ip -4 -o addr show dev "${GWCTX_IFACE}" scope global 2>/dev/null | awk '{print $4}' | head -n1 || true
)"
if [[ -z "${IFACE_CIDR}" ]]; then
  log "ERROR: interface ${GWCTX_IFACE} has no global IPv4 address"
  ip -4 -o addr show dev "${GWCTX_IFACE}" || true
  exit 1
fi
IFACE_IP="${IFACE_CIDR%%/*}"

BASE_CG_PATH="$(
  awk -F: '$2=="" {print $3; exit} $2=="unified" {print $3; exit}' /proc/self/cgroup || true
)"
if [[ -z "${BASE_CG_PATH}" ]]; then
  log "ERROR: could not determine cgroup path from /proc/self/cgroup"
  exit 1
fi
[[ "${BASE_CG_PATH}" == /* ]] || BASE_CG_PATH="/${BASE_CG_PATH}"

LEAF_NAME="gwshell-leaf-${TABLE_ID}-$$"
LEAF_FS_DIR="/sys/fs/cgroup${BASE_CG_PATH}/${LEAF_NAME}"
LEAF_CG_PATH="${BASE_CG_PATH}/${LEAF_NAME}"

if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
  mkdir -p "${LEAF_FS_DIR}"
  echo $$ > "${LEAF_FS_DIR}/cgroup.procs"
else
  log "ERROR: cgroup v2 not detected; cannot create leaf cgroup"
  exit 1
fi

RCFILE="/run/gwctx.${TABLE_ID}.$$.rc"
TMPHOME="/run/gwctx-home.${TABLE_ID}.$$/"

cleanup() {
  set +e

  # remove SNAT first (best effort)
  iptables -t nat -D POSTROUTING -m mark --mark "${MARK_HEX}/0xffffffff" -o "${GWCTX_IFACE}" \
    -j SNAT --to-source "${IFACE_IP}" 2>/dev/null || true

  iptables -t mangle -D OUTPUT -m cgroup --path "${LEAF_CG_PATH}" \
    -j MARK --set-xmark "${MARK_HEX}/0xffffffff" 2>/dev/null || true

  ip -4 rule del pref "${RULE_PRIO}" 2>/dev/null || true
  ip -4 route flush table "${TABLE_ID}" 2>/dev/null || true
  ip -4 route flush cache 2>/dev/null || true

  rm -f "${RCFILE}" 2>/dev/null || true
  rm -rf "${TMPHOME}" 2>/dev/null || true
  rmdir "${LEAF_FS_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# mark packets from this shell context
iptables -t mangle -A OUTPUT -m cgroup --path "${LEAF_CG_PATH}" \
  -j MARK --set-xmark "${MARK_HEX}/0xffffffff"

# policy route marked packets
ip -4 rule add pref "${RULE_PRIO}" fwmark "${MARK_HEX}/0xffffffff" lookup "${TABLE_ID}"

# session table: default via user-supplied gateway
ip -4 route replace "${GWCTX_GW}/32" dev "${GWCTX_IFACE}" scope link table "${TABLE_ID}"
ip -4 route replace default via "${GWCTX_GW}" dev "${GWCTX_IFACE}" onlink table "${TABLE_ID}"
ip -4 route flush cache

# CRITICAL: force correct source IP for marked packets leaving via GWCTX_IFACE
iptables -t nat -A POSTROUTING -m mark --mark "${MARK_HEX}/0xffffffff" -o "${GWCTX_IFACE}" \
  -j SNAT --to-source "${IFACE_IP}"

EXT_IP="(unavailable)"
if command -v curl >/dev/null 2>&1; then
  set +e
  EXT_IP="$(
    curl -4 -sS --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null \
      | tr -d '\r\n' | head -c 64
  )"
  rc=$?
  set -e
  if [[ $rc -ne 0 || -z "${EXT_IP}" ]]; then
    EXT_IP="(unavailable)"
  fi
fi

log "=== GW CONTEXT START ==="
log "IFACE:         ${GWCTX_IFACE} (addr: ${IFACE_CIDR})"
log "GW (DEFAULT):  ${GWCTX_GW}"
log "External IP:   ${EXT_IP}"
log "MARK:          ${MARK_HEX}"
log "TABLE_ID:      ${TABLE_ID}"
log "RULE_PRIO:     ${RULE_PRIO}"
log "CGROUP:        ${LEAF_CG_PATH}"
log "LOG:           ${GWCTX_LOG}"
log ""

cat >"${RCFILE}" <<PROFILE
export GWCTX_IFACE="${GWCTX_IFACE}"
export GWCTX_GW="${GWCTX_GW}"
export MARK_HEX="${MARK_HEX}"
export TABLE_ID="${TABLE_ID}"

gw-route-get() {
  local dst="\${1:-1.1.1.1}"
  ip -4 route get "\$dst" mark "\${MARK_HEX}"
}

gw-check() {
  echo "== policy rule =="
  ip -4 rule | grep -n "lookup \${TABLE_ID}" || true
  echo
  echo "== table routes =="
  ip -4 route show table "\${TABLE_ID}" || true
  echo
  echo "== nat postrouting (snat for mark) =="
  iptables -t nat -S POSTROUTING | grep "mark.*\${MARK_HEX}" || true
}

export PS1="(gwshell:\${TABLE_ID} ${GWCTX_IFACE}->${GWCTX_GW}) \${PS1}"
PROFILE

mkdir -p "${TMPHOME}"
cat >"${TMPHOME}/.bashrc" <<BASHRC
[ -f "${RCFILE}" ] && . "${RCFILE}"
BASHRC

exec env HOME="${TMPHOME}" bash -i
EOF
  chmod 0755 "${GWCTX_PATH}"

  info "Writing ${GWSHELL_PATH}"
  cat >"${GWSHELL_PATH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<USAGE
Usage:
  sudo gwshell -i <iface> <gateway-ip>

Example:
  sudo gwshell -i ens160 192.168.1.1
  sudo gwshell -i wls192 192.168.3.1
USAGE
  exit 2
}

IFACE=""
while getopts ":i:" opt; do
  case "$opt" in
    i) IFACE="$OPTARG" ;;
    *) usage ;;
  esac
done
shift $((OPTIND-1))

GW="${1:-}"
[[ -n "${IFACE}" ]] || usage
[[ -n "${GW}" ]] || usage
[[ $# -eq 1 ]] || usage

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: must run as root (use sudo)" >&2
  exit 1
fi

if ! ip link show dev "${IFACE}" >/dev/null 2>&1; then
  echo "ERROR: interface not found: ${IFACE}" >&2
  exit 1
fi

IFACE_CIDR="$(ip -4 -o addr show dev "${IFACE}" scope global | awk '{print $4}' | head -n1 || true)"
if [[ -z "${IFACE_CIDR}" ]]; then
  echo "ERROR: interface ${IFACE} has no global IPv4 address" >&2
  ip -4 -o addr show dev "${IFACE}" >&2 || true
  exit 1
fi

if ! [[ "${GW}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "ERROR: gateway must be an IPv4 address: ${GW}" >&2
  exit 1
fi
IFS=. read -r a b c d <<<"${GW}"
for oct in "$a" "$b" "$c" "$d"; do
  if ((oct < 0 || oct > 255)); then
    echo "ERROR: invalid IPv4 address: ${GW}" >&2
    exit 1
  fi
done

# On-link check (avoid "GW on wrong iface" foot-gun)
if ! ip -4 route get "${GW}" 2>/dev/null | grep -q " dev ${IFACE}"; then
  echo "ERROR: gateway ${GW} is not reachable on-link via ${IFACE} (iface addr: ${IFACE_CIDR})" >&2
  echo "Hint: choose the interface that is in the same L2/subnet as the gateway." >&2
  ip -4 route get "${GW}" >&2 || true
  exit 1
fi

TABLE_ID="$(shuf -i 2000-4999 -n 1)"
MARK_HEX="$(printf '0x%X' $((0x20000 + (RANDOM & 0x0FFF))))"
RULE_PRIO="$(shuf -i 10010-10999 -n 1)"
LOG="/run/gwshell-${TABLE_ID}.log"

echo "Starting gwctx-${TABLE_ID}.service (log: ${LOG})" >&2

exec systemd-run --quiet --pty --service-type=simple \
  --unit="gwctx-${TABLE_ID}.service" \
  --property="KillMode=mixed" \
  --property="TimeoutStopSec=5s" \
  env \
    GWCTX_IFACE="${IFACE}" \
    GWCTX_GW="${GW}" \
    MARK_HEX="${MARK_HEX}" \
    TABLE_ID="${TABLE_ID}" \
    RULE_PRIO="${RULE_PRIO}" \
    GWCTX_LOG="${LOG}" \
    /usr/local/sbin/gwctx-shell
EOF
  chmod 0755 "${GWSHELL_PATH}"
}

post_install_notes() {
  cat >&2 <<'NOTES'

Installed:
  /usr/local/sbin/gwshell
  /usr/local/sbin/gwctx-shell

Usage:
  sudo gwshell -i <iface> <gateway-ip>

Example:
  sudo gwshell -i ens160 192.168.1.1
  sudo gwshell -i wls192 192.168.3.1

Debug:
  gw-check
  gw-route-get 1.1.1.1
  cat /run/gwshell-<TABLE_ID>.log

NOTES
}

main() {
  require_root
  check_deps
  install_files
  post_install_notes
  info "Done."
}

main "$@"
