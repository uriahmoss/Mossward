#!/bin/sh
set -eu
worker_binary=${1:-}
worker_config=${2:-}
if [ "$#" -ne 2 ] || [ -z "$worker_binary" ] || [ -z "$worker_config" ]; then
    echo 'usage: install-mossward-worker.sh BINARY CONFIG' >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo 'installation must run as root' >&2
    exit 1
fi
if [ ! -f "$worker_binary" ] || [ ! -f "$worker_config" ] || [ -L "$worker_binary" ] || [ -L "$worker_config" ]; then
    echo 'binary/configuration must be regular files, not symbolic links' >&2
    exit 1
fi
if [ -e /usr/local/bin/mossward-worker ] || [ -e /etc/mossward-worker/worker.json ] || [ -e /etc/systemd/system/mossward-worker.service ]; then
    echo 'existing installation detected; refusing to overwrite it' >&2
    exit 1
fi
for worker_directory in /etc/mossward-worker /var/lib/mossward-worker; do
    if [ -L "$worker_directory" ]; then
        echo 'managed worker directory must not be a symbolic link' >&2
        exit 1
    fi
done
if getent passwd mossward-worker >/dev/null 2>&1 && [ "$(id -u mossward-worker)" -eq 0 ]; then
    echo 'worker service account must not be root' >&2
    exit 1
fi
if ! getent group mossward-worker >/dev/null 2>&1; then groupadd --system mossward-worker; fi
if ! getent passwd mossward-worker >/dev/null 2>&1; then
    useradd --system --gid mossward-worker --home-dir /var/lib/mossward-worker --shell /usr/sbin/nologin mossward-worker
fi
install -d -o root -g mossward-worker -m 0750 /etc/mossward-worker
install -d -o mossward-worker -g mossward-worker -m 0700 /var/lib/mossward-worker
install -o root -g root -m 0755 "$worker_binary" /usr/local/bin/mossward-worker
install -o root -g mossward-worker -m 0640 "$worker_config" /etc/mossward-worker/worker.json
install -o root -g root -m 0644 "$(dirname "$0")/mossward-worker.service" /etc/systemd/system/mossward-worker.service
systemctl daemon-reload
echo 'Worker installed, not started. Provision its enrolled identity and verify as the service account before enabling.'
