#!/usr/bin/env bash
# Config manager and residential manager: install on a dedicated Linux VPS.
set -Eeuo pipefail

# A shared bounded downloader for the standalone bootstrap and pinned dependencies.
# Use a subshell so its cleanup trap never replaces the bootstrap's cleanup trap.
cmrm_download() (
    set -Eeuo pipefail
    local label=$1 output=$2 limit=$3 pin=$4 budget=$5
    shift 5
    local family=${CMRM_IP_VERSION:-auto} url mode remaining cap metadata status digest
    local deadline attempt=0 partial
    local -a modes transport
    case "$family" in
        auto) modes=(auto ipv4-http1) ;;
        4) modes=(ipv4 ipv4-http1) ;;
        6) modes=(ipv6 ipv6-http1) ;;
        *) echo 'CMRM_IP_VERSION must be auto, 4 or 6.' >&2; return 2 ;;
    esac
    [[ $limit =~ ^[0-9]+$ && $budget =~ ^[1-9][0-9]*$ ]] || return 2
    [[ -z $pin || $pin =~ ^[a-fA-F0-9]{64}$ ]] || return 2
    deadline=$((SECONDS + budget))
    partial=$(mktemp -- "${output}.part.XXXXXX") || return 1
    trap 'rm -f -- "$partial"' EXIT
    for url in "$@"; do
        [[ $url == https://* ]] || { echo 'Download URL must use HTTPS.' >&2; return 2; }
        for mode in "${modes[@]}"; do
            remaining=$((deadline - SECONDS))
            ((remaining > 0)) || break 2
            cap=$remaining
            transport=()
            case "$mode" in
                ipv4) transport=(--ipv4) ;;
                ipv6) transport=(--ipv6) ;;
                ipv4-http1) transport=(--ipv4 --http1.1) ;;
                ipv6-http1) transport=(--ipv6 --http1.1) ;;
            esac
            attempt=$((attempt + 1))
            printf '[download] %s | attempt %s | %s | %s\n' "$label" "$attempt" "$mode" "$url"
            if metadata=$(curl --disable --fail --location --silent --show-error \
                --proto '=https' --proto-redir '=https' --max-redirs 5 \
                --connect-timeout 8 --max-time "$cap" --speed-limit 1 --speed-time 20 \
                --max-filesize "$limit" "${transport[@]}" \
                --write-out '%{size_download} bytes in %{time_total}s' --output "$partial" "$url"); then
                if [[ ! -s $partial ]]; then
                    echo '[download] Empty response; trying the next transport or source.' >&2
                    continue
                fi
                if (($(stat -c %s -- "$partial") > limit)); then
                    echo '[download] Response exceeds the size limit; refusing this file.' >&2
                    return 1
                fi
                if [[ -n $pin ]]; then
                    digest=$(sha256sum -- "$partial") || return 1
                    if [[ ${digest%% *} != "${pin,,}" ]]; then
                        echo '[download] Checksum mismatch; refusing this file.' >&2
                        return 1
                    fi
                fi
                mv -f -- "$partial" "$output" || return 1
                printf '[download] %s complete: %s\n' "$label" "$metadata"
                return 0
            else
                status=$?
                printf '[download] %s failed (curl %s); trying the next transport or source.\n' "$label" "$status" >&2
            fi
        done
    done
    printf '[download] %s failed within the %ss retry budget. Check server DNS/HTTPS access to the URLs above, then rerun.\n' "$label" "$budget" >&2
    return 1
)

cmrm_install() {
[[ $EUID == 0 ]] || { echo 'Run as root (sudo -i).'; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'This release supports Linux amd64 only.'; exit 1; }
source /etc/os-release
case "$ID:$VERSION_ID" in ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;; *) echo 'Supported: Ubuntu 24.04/26.04, Debian 12/13, amd64 with systemd and cgroup v2.'; exit 1;; esac
[[ -d /run/systemd/system && -f /sys/fs/cgroup/cgroup.controllers ]] || { echo 'A systemd host with cgroup v2 is required.'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
printf '[install] Installing system prerequisites\n'
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl python3 python3-venv openssl nginx nftables iproute2 bubblewrap util-linux tar gzip unzip gcc libc6-dev
if [[ -f /etc/config-repair/egress-access-mmdb.json ]]; then
    apt-get install -y --no-install-recommends python3-maxminddb
fi
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! -f "$SOURCE_DIR/deploy/install.py" ]]; then
    WORK_DIR=$(mktemp -d /var/tmp/cmrm-source.XXXXXX)
    trap 'rm -rf -- "$WORK_DIR"' EXIT
    REF=${CMRM_REF:-main}
    [[ $REF =~ ^[a-zA-Z0-9._/-]+$ && $REF != *..* ]] || { echo 'Invalid CMRM_REF'; exit 1; }
    cmrm_download 'Project source' "$WORK_DIR/source.tar.gz" 16777216 '' 120 \
      "https://codeload.github.com/rezajafari0970/config-manager-and-residential-manager/tar.gz/$REF" \
      "https://github.com/rezajafari0970/config-manager-and-residential-manager/archive/$REF.tar.gz"
    python3 - "$WORK_DIR" <<'PY'
import pathlib,sys,tarfile
p=pathlib.Path(sys.argv[1])
with tarfile.open(p/'source.tar.gz') as t:
    if sum(x.size for x in t)>64*1024*1024: raise SystemExit('Source archive too large')
    t.extractall(p/'source',filter='data')
PY
    roots=("$WORK_DIR"/source/*)
    [[ ${#roots[@]} == 1 && -f "${roots[0]}/deploy/install.py" ]] || exit 1
    SOURCE_DIR=${roots[0]}
fi
python3 -u "$SOURCE_DIR/deploy/install.py"

}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    if [[ ${1:-} == --download ]]; then
        [[ $# == 5 ]] || { echo 'Usage: install.sh --download URL OUTPUT MAX_BYTES SHA256_OR_EMPTY' >&2; exit 2; }
        cmrm_download "$(basename -- "$3")" "$3" "$4" "$5" 300 "$2"
    else
        cmrm_install "$@"
    fi
fi
