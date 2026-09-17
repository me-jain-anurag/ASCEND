#!/bin/bash
# Generate host keys on first boot, then run sshd in the foreground.
set -e
ssh-keygen -A >/dev/null 2>&1
exec /usr/sbin/sshd -D -e
