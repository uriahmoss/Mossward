#!/bin/sh
# Reviewed local administration only; never source the service environment.
set -eu
umask 077
binary_path=/usr/local/bin/mossward
config_directory=/etc/mossward
config_path=$config_directory/mossward.env
receipt_path=$config_directory/managed-install
previous_binary=$config_directory/mossward.previous
state_directory=/var/lib/mossward
unit_path=/etc/systemd/system/mossward.service
service_name=mossward.service
readiness_url=${MOSSWARD_READINESS_URL:-http://127.0.0.1:8080/api/ready}
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

fail() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "INFO: $*"; }
regular_file() { [ -f "$1" ] && [ ! -L "$1" ] || fail 'Expected a regular, non-symlink file.'; }
absent() { [ ! -e "$1" ] && [ ! -L "$1" ] || fail "Refusing to overwrite $1"; }
safe_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] || fail 'Managed parent must be a real directory.'
    owner=$(stat -c %u "$1")
    mode=$(stat -c %a "$1")
    [ "$owner" = 0 ] && [ "$((0$mode & 022))" -eq 0 ] || fail 'Managed parent must be root-owned and not group/world-writable.'
}
require_managed() {
    regular_file "$receipt_path"
    [ "$(cat "$receipt_path")" = mossward-linux-managed-v1 ] || fail 'Unrecognized installation receipt.'
    [ "$(stat -c %u "$receipt_path")" = 0 ] || fail 'Installation receipt must be root-owned.'
    regular_file "$config_path"
    regular_file "$binary_path"
    regular_file "$unit_path"
}
require_stopped() {
    status=$(systemctl show -p ActiveState --value "$service_name")
    case "$status" in inactive|failed) ;; *) fail 'Stop Mossward before offline backup/update.' ;; esac
}
install_server() {
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || fail 'usage: manage-mossward-server.sh install BINARY [ENV_FILE]'
    regular_file "$1"
    absent "$binary_path"
    absent "$unit_path"
    if [ -e "$config_path" ] || [ -L "$config_path" ]; then
        regular_file "$receipt_path"
        [ "$(cat "$receipt_path")" = mossward-linux-managed-v1 ] || fail 'Existing configuration is not a managed installation.'
        regular_file "$config_path"
        [ "$#" -eq 1 ] || fail 'Retained configuration exists; omit ENV_FILE to reuse it.'
    else
        [ "$#" -eq 2 ] || fail 'Fresh installation requires ENV_FILE.'
        regular_file "$2"
        absent "$receipt_path"
    fi
    if getent passwd mossward >/dev/null 2>&1; then
        [ "$(id -u mossward)" -ne 0 ] || fail 'Mossward account cannot be root.'
    else
        getent group mossward >/dev/null 2>&1 || groupadd --system mossward
        useradd --system --gid mossward --home-dir "$state_directory" --shell /usr/sbin/nologin mossward
    fi
    if [ -e "$state_directory" ]; then
        [ "$(stat -c %u "$state_directory")" = "$(id -u mossward)" ] || fail 'Existing state must belong to the Mossward account.'
    fi
    install -d -o root -g mossward -m 0750 "$config_directory"
    install -d -o mossward -g mossward -m 0700 "$state_directory"
    if [ "$#" -eq 2 ]; then install -o root -g mossward -m 0640 "$2" "$config_path"; fi
    install -o root -g root -m 0755 "$1" "$binary_path"
    install -o root -g root -m 0644 "$script_directory/mossward.service" "$unit_path"
    printf '%s\n' mossward-linux-managed-v1 > "$receipt_path"
    chmod 0600 "$receipt_path"
    systemctl daemon-reload
    info 'Installed, not started. Review configuration and complete localhost setup before exposing HTTPS.'
}
uninstall_server() {
    [ "$#" -eq 0 ] || fail 'Uninstall takes no arguments; destructive purge is not supported.'
    require_managed
    systemctl stop "$service_name"
    require_stopped
    systemctl disable "$service_name"
    rm -- "$unit_path" "$binary_path"
    systemctl daemon-reload
    info 'Service and executable removed. Configuration, database, keys, certificates, previous binary and account retained.'
}
update_server() {
    [ "$#" -eq 4 ] && [ "$2" = --backup ] && [ "$4" = --confirm-current-offline-backup ] || fail 'usage: update BINARY --backup ARCHIVE --confirm-current-offline-backup'
    require_managed
    case "$readiness_url" in http://127.0.0.1:*/*|http://localhost:*/*|https://*) ;; *) fail 'Readiness requires loopback HTTP or verified HTTPS.' ;; esac
    regular_file "$1"
    regular_file "$3"
    require_stopped
    absent "$previous_binary"
    # Inspect without starting a database or interpreting environment-file shell code.
    # Clear inherited settings: inspect needs only the archive, not production secrets.
    env -i PATH=/usr/bin:/bin "$binary_path" backup inspect --input "$3" >/dev/null || fail 'Backup inspection failed; deployment unchanged.'
    install -o root -g root -m 0700 "$binary_path" "$previous_binary"
    staged=$(mktemp /usr/local/bin/mossward-update.XXXXXXXX)
    trap 'rm -f -- "$staged"' EXIT HUP INT TERM
    install -o root -g root -m 0755 "$1" "$staged"
    mv -- "$staged" "$binary_path"
    trap - EXIT HUP INT TERM
    if ! systemctl start "$service_name"; then
        systemctl stop "$service_name" || echo 'WARNING: Could not confirm service stop.' >&2
        fail 'Service start failed; previous executable retained. Diagnose before any database rollback.'
    fi
    ready=false
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if curl --silent --fail --max-time 3 --noproxy '*' "$readiness_url" >/dev/null; then ready=true; break; fi
        sleep 1
    done
    if [ "$ready" != true ]; then
        systemctl stop "$service_name"
        fail 'Readiness failed; service stopped, new/previous executables retained. Diagnose before restoring an offline backup; no automatic database rollback.'
    fi
    info 'Updated and ready. Retain verified backup and previous executable; archive the previous executable before another update.'
}

[ "$(id -u)" -eq 0 ] || fail 'Run as root.'
for directory in /usr /usr/local /usr/local/bin /etc /etc/systemd /etc/systemd/system /var /var/lib /run; do safe_directory "$directory"; done
lock_path=/run/mossward-deployment.lock
[ ! -L "$lock_path" ] || fail 'Deployment lock must not be a symlink.'
exec 9> "$lock_path"
flock -n 9 || fail 'Another server lifecycle operation is in progress.'
for directory in "$config_directory" "$state_directory"; do
    [ ! -L "$directory" ] || fail 'Managed directories must not be symlinks.'
done
if [ -e "$config_directory" ]; then safe_directory "$config_directory"; fi
action=${1:-}
[ "$#" -gt 0 ] || fail 'usage: manage-mossward-server.sh install|uninstall|update ...'
shift
case "$action" in
    install) install_server "$@" ;;
    uninstall) uninstall_server "$@" ;;
    update) update_server "$@" ;;
    *) fail 'Unknown action.' ;;
esac
