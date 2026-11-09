#!/bin/sh
set -eu
for account in root ops; do
  if [ "$account" = root ]; then userdir=/root; else userdir=/home/ops; fi
  mkdir -p "$userdir/.ssh"
  cp /fixture/authorized_keys "$userdir/.ssh/authorized_keys"
  chown -R "$account:$account" "$userdir/.ssh"
  chmod 700 "$userdir/.ssh"
  chmod 600 "$userdir/.ssh/authorized_keys"
  passwd -d "$account" >/dev/null
 done
ssh-keygen -A >/dev/null 2>&1
cat > /etc/nginx/nginx.conf <<'CONFIG'
worker_processes 1;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
events { worker_connections 32; }
http { access_log off; server { listen 127.0.0.1:8080; return 200 'fixture'; } }
CONFIG
/usr/sbin/nginx
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=prohibit-password
