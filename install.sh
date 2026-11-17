#!/usr/bin/env bash
# Config manager and residential manager: install on a dedicated Linux VPS.
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'Run as root (sudo -i).'; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'This release supports Linux amd64 only.'; exit 1; }
source /etc/os-release
case "$ID:$VERSION_ID" in ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;; *) echo 'Supported: Ubuntu 24.04/26.04, Debian 12/13, amd64 with systemd and cgroup v2.'; exit 1;; esac
[[ -d /run/systemd/system && -f /sys/fs/cgroup/cgroup.controllers ]] || { echo 'A systemd host with cgroup v2 is required.'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl python3 python3-venv openssl nginx nftables iproute2 bubblewrap util-linux tar gzip unzip gcc libc6-dev
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! -f "$SOURCE_DIR/deploy/install.py" ]]; then
    WORK_DIR=$(mktemp -d /var/tmp/cmrm-source.XXXXXX)
    trap 'rm -rf -- "$WORK_DIR"' EXIT
    REF=${CMRM_REF:-main}
    [[ $REF =~ ^[a-zA-Z0-9._/-]+$ && $REF != *..* ]] || { echo 'Invalid CMRM_REF'; exit 1; }
    curl --fail --location --retry 3 --connect-timeout 20 --max-time 180 --max-filesize 16777216 \
      "https://github.com/rezajafari0970/config-manager-and-residential-manager/archive/$REF.tar.gz" -o "$WORK_DIR/source.tar.gz"
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
python3 "$SOURCE_DIR/deploy/install.py"
