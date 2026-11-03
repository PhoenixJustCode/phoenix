#!/bin/bash
# one-time idempotent server setup for CI/CD; run as root from a copy of this directory
set -euo pipefail
cd "$(dirname "$0")"

readonly ROOT=/opt/phoenix
readonly LEGACY_DIR=/var/www/phoenix
readonly ENV_FILE=/etc/phoenix/env
readonly DB=phoenix_data
readonly APP_ROLE=phoenix_app
readonly SITE_URL=https://phoenixjustcode.ru/
readonly BACKUPS=/root/backups
readonly UNIT=/etc/systemd/system/phoenix.service
readonly CHECK_ATTEMPTS=20

step() { echo "==> $*"; }
psql_su() { runuser -u postgres -- psql -q -v ON_ERROR_STOP=1 "$@"; }

[[ -s deploy_key.pub ]] || { echo "deploy_key.pub is missing" >&2; exit 1; }
umask 022

step "users"
id phoenix >/dev/null 2>&1 ||
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin phoenix
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy
passwd -l deploy >/dev/null

step "directories"
install -d -m 755 "$ROOT" "${ROOT}/releases" /etc/phoenix
install -d -m 750 -o deploy -g deploy "${ROOT}/incoming"
install -d -m 700 /var/backups/phoenix "$BACKUPS"

step "scripts"
install -m 755 phoenix-deploy phoenix-ssh-gate pg-backup phoenix-monitor /usr/local/bin/

step "deploy key: forced command only, file owned by root so deploy can't lift the limits"
install -d -m 755 -o root -g root /home/deploy/.ssh
printf 'restrict,command="/usr/local/bin/phoenix-ssh-gate" %s\n' "$(cat deploy_key.pub)" \
  >/home/deploy/.ssh/authorized_keys
chown root:root /home/deploy/.ssh/authorized_keys
chmod 644 /home/deploy/.ssh/authorized_keys

step "sudo: deploy may run only phoenix-deploy"
echo 'deploy ALL=(root) NOPASSWD: /usr/local/bin/phoenix-deploy' >/etc/sudoers.d/phoenix-deploy.new
chmod 440 /etc/sudoers.d/phoenix-deploy.new
visudo -cqf /etc/sudoers.d/phoenix-deploy.new
mv /etc/sudoers.d/phoenix-deploy.new /etc/sudoers.d/phoenix-deploy

step "database: own role for the app, superuser only via local peer auth"
if [[ ! -s $ENV_FILE ]]; then
  app_pw=$(openssl rand -hex 24)
  psql_su <<SQL
BEGIN;
DO \$\$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
    ALTER ROLE ${APP_ROLE} LOGIN PASSWORD '${app_pw}';
  ELSE
    CREATE ROLE ${APP_ROLE} LOGIN PASSWORD '${app_pw}';
  END IF;
END \$\$;
ALTER DATABASE ${DB} OWNER TO ${APP_ROLE};
ALTER ROLE postgres PASSWORD NULL;
COMMIT;
SQL
  psql_su -d "$DB" <<SQL
BEGIN;
ALTER TABLE visits OWNER TO ${APP_ROLE};
ALTER TABLE admins OWNER TO ${APP_ROLE};
ALTER TABLE sessions OWNER TO ${APP_ROLE};
COMMIT;
SQL
  (umask 077 && printf 'DATABASE_URL=postgres://%s:%s@127.0.0.1:5432/%s?sslmode=disable\n' \
    "$APP_ROLE" "$app_pw" "$DB" >"$ENV_FILE")
fi
chmod 600 "$ENV_FILE"

step "legacy .env: no secrets left, the old binary gets DATABASE_URL from the unit"
cp -n "${LEGACY_DIR}/.env" "${BACKUPS}/phoenix.env.legacy"
chmod 600 "${BACKUPS}/phoenix.env.legacy"
sed -i 's/^DB_USER=.*/DB_USER=/; s/^DB_PASSWORD=.*/DB_PASSWORD=/' "${LEGACY_DIR}/.env"

step "legacy release: the old binary stays the rollback target until a new release passes checks"
install -d -m 755 "${ROOT}/releases/legacy"
printf '#!/bin/sh\ncd %s && exec ./phoenix\n' "$LEGACY_DIR" >"${ROOT}/releases/legacy/phoenix"
chmod 755 "${ROOT}/releases/legacy/phoenix"
[[ -e ${ROOT}/current ]] || ln -s "${ROOT}/releases/legacy" "${ROOT}/current"

step "systemd unit"
if ! cmp -s phoenix.service "$UNIT"; then
  cp -n "$UNIT" "${BACKUPS}/phoenix.service.legacy"
  install -m 644 phoenix.service "$UNIT"
  systemctl daemon-reload
  systemctl restart phoenix
  for ((i = 0; i < CHECK_ATTEMPTS; i++)); do
    curl -fsS -m 5 -o /dev/null "$SITE_URL" && break
    sleep 1
  done
  if ((i == CHECK_ATTEMPTS)); then
    echo "site is down under the new unit, restoring the old one" >&2
    # the old unit has no DATABASE_URL, so the legacy .env gets the new role back
    app_pw=$(sed -E 's#^DATABASE_URL=postgres://[^:]+:([^@]+)@.*#\1#' "$ENV_FILE")
    sed -i "s/^DB_USER=.*/DB_USER=${APP_ROLE}/; s/^DB_PASSWORD=.*/DB_PASSWORD=${app_pw}/" \
      "${LEGACY_DIR}/.env"
    install -m 644 "${BACKUPS}/phoenix.service.legacy" "$UNIT"
    systemctl daemon-reload
    systemctl restart phoenix
    exit 1
  fi
fi
systemctl enable phoenix >/dev/null 2>&1

step "backup with restore check"
systemctl start pg-backup.service
journalctl -u pg-backup -n 4 --no-pager -o cat

step "done"
echo "phoenix: $(systemctl is-active phoenix), current -> $(readlink "${ROOT}/current")"
echo "site: $(curl -s -o /dev/null -w '%{http_code}' "$SITE_URL")"
