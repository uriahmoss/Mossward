#!/bin/sh
set -eu

agent_binary=${1:-}
agent_config=${2:-}

if [ -z "$agent_binary" ] || [ -z "$agent_config" ]; then
	echo "usage: install-mossward-agent.sh BINARY CONFIG" >&2
	exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
	echo "installation must run as root" >&2
	exit 1
fi
if [ ! -f "$agent_binary" ] || [ ! -f "$agent_config" ]; then
	echo "binary and configuration must be regular files" >&2
	exit 1
fi

if ! getent group mossward-agent >/dev/null 2>&1; then
	groupadd --system mossward-agent
fi
if ! getent passwd mossward-agent >/dev/null 2>&1; then
	useradd --system --gid mossward-agent --home-dir /var/lib/mossward-agent --shell /usr/sbin/nologin mossward-agent
fi

install -d -o root -g mossward-agent -m 0750 /etc/mossward-agent
install -d -o mossward-agent -g mossward-agent -m 0700 /var/lib/mossward-agent
install -o root -g root -m 0755 "$agent_binary" /usr/local/bin/mossward-agent
install -o root -g mossward-agent -m 0640 "$agent_config" /etc/mossward-agent/agent.json
install -o root -g root -m 0644 "$(dirname "$0")/mossward-agent.service" /etc/systemd/system/mossward-agent.service
systemctl daemon-reload

echo "Mossward agent installed but not started. Enroll it, then run:"
	echo "  cat /root/mossward-enrollment-token | runuser -u mossward-agent -- /usr/local/bin/mossward-agent enroll --config /etc/mossward-agent/agent.json --token-stdin"
echo "  systemctl enable --now mossward-agent.service"
