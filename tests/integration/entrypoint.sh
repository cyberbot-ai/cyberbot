#!/bin/sh
set -eu
cp /fixture/authorized_keys /home/ops/.ssh/authorized_keys
chown ops:ops /home/ops/.ssh/authorized_keys
chmod 600 /home/ops/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o PermitRootLogin=no -o AllowUsers=ops
