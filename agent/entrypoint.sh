#!/bin/bash

# EDR Agent Entrypoint Script
set -e

echo "=== Starting EDR Agent ==="

# Start rsyslog
echo "Starting rsyslog..."
rsyslogd || {
    echo "Failed to start rsyslogd, trying alternative..."
    /usr/sbin/rsyslogd -n &
}

# Start SSH daemon
echo "Starting SSH daemon..."
mkdir -p /var/run/sshd
/usr/sbin/sshd -D &

# Start Vector (if config exists)
if [ -f /etc/vector/vector.toml ]; then
    echo "Starting Vector..."
    /usr/local/bin/vector --config /etc/vector/vector.toml &
else
    echo "Vector config not found, skipping..."
fi

# Keep container running
echo "=== EDR Agent started successfully ==="
echo "Services running:"
echo "- SSH: port 22"
echo "- Vector: port 8686"
echo "- Rsyslog: localhost:514"

# Keep container alive
tail -f /dev/null
