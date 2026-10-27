#!/bin/sh
# Installs cbsd-web (and CBSD itself when missing) on FreeBSD.
#
#   sh scripts/install.sh            # binary ./cbsd-web next to this script or in the repo root
#   CBSDWEB_LISTEN=127.0.0.1:8443 sh scripts/install.sh
#
# Idempotent: re-running upgrades the binary and keeps users and configuration.
set -eu

PREFIX=/usr/local
BIN=${PREFIX}/sbin/cbsd-web
ETC=${PREFIX}/etc/cbsd-web
DATA=/var/db/cbsd-web
LOG=/var/log/cbsd-web
USER=cbsdweb
LISTEN=${CBSDWEB_LISTEN:-0.0.0.0:8443}

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "FreeBSD" ] || die "this installer is for FreeBSD"
[ "$(id -u)" -eq 0 ] || die "run as root"

here=$(cd "$(dirname "$0")" && pwd)
src=""
if [ -f "${here}/../go.mod" ]; then
	# Source checkout: always rebuild, so 'git pull' + install never reuses an old binary.
	say "building cbsd-web from source"
	command -v go >/dev/null 2>&1 || pkg install -y go
	rev=$(cd "${here}/.." && git rev-parse --short HEAD 2>/dev/null || true)
	ldver=""
	ver=$(sed -n 's/^var version = "\(.*\)"/\1/p' "${here}/../cmd/cbsd-web/main.go")
	[ -n "$rev" ] && ldver="-X main.version=${ver}-${rev}"
	(cd "${here}/.." && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w ${ldver}" -o cbsd-web ./cmd/cbsd-web) || die "build failed"
	src="${here}/../cbsd-web"
else
	for c in "${here}/cbsd-web" "${here}/../cbsd-web" "${here}/../bin/cbsd-web-freebsd-$(uname -m)"; do
		[ -f "$c" ] && { src=$c; break; }
	done
	[ -n "$src" ] || die "cbsd-web binary not found next to the installer"
fi

say "installing packages: cbsd sudo tmux"
pkg info -e cbsd || pkg install -y cbsd
pkg info -e sudo || pkg install -y sudo
# bstart refuses to start bhyve VMs without tmux.
pkg info -e tmux || pkg install -y tmux

say "creating user ${USER}"
if ! pw usershow "${USER}" >/dev/null 2>&1; then
	pw useradd -n "${USER}" -c "CBSD web interface" -d /nonexistent -s /usr/sbin/nologin -w no
fi
# CBSD keeps its SQLite databases (mode 0660, WAL) readable only by group cbsd.
if pw groupshow cbsd >/dev/null 2>&1 && ! id -Gn "${USER}" | tr ' ' '\n' | grep -qx cbsd; then
	pw groupmod cbsd -m "${USER}"
fi

say "installing files"
install -m 0555 -o root -g wheel "$src" "$BIN"
install -d -m 0755 -o root -g wheel "$ETC"
install -d -m 0750 -o "$USER" -g "$USER" "$DATA" "$LOG"
if [ ! -f "${ETC}/cbsd-web.conf" ]; then
	sed "s#\"listen\": \"0.0.0.0:8443\"#\"listen\": \"${LISTEN}\"#" "${here}/../deploy/cbsd-web.conf.sample" > "${ETC}/cbsd-web.conf"
	chmod 0644 "${ETC}/cbsd-web.conf"
fi
# ISO images uploaded from the web UI: <workdir>/src/iso/upload, owned by the
# daemon so it can write them without sudo (bhyve reads them as root).
workdir=$(sed -n 's/^[[:space:]]*"workdir":[[:space:]]*"\([^"]*\)".*/\1/p' "${ETC}/cbsd-web.conf")
[ -n "$workdir" ] || workdir=$(sysrc -n cbsd_workdir 2>/dev/null || echo /usr/jails)
if [ -f "${workdir}/var/db/local.sqlite" ]; then
	[ -d "${workdir}/src/iso" ] || mkdir -p "${workdir}/src/iso"
	install -d -m 0755 -o "$USER" -g "$USER" "${workdir}/src/iso/upload"
fi
install -d -m 0750 ${PREFIX}/etc/sudoers.d
install -m 0440 -o root -g wheel "${here}/../deploy/sudoers" ${PREFIX}/etc/sudoers.d/cbsd-web
visudo -c -f ${PREFIX}/etc/sudoers.d/cbsd-web >/dev/null || { rm -f ${PREFIX}/etc/sudoers.d/cbsd-web; die "sudoers syntax check failed"; }
install -m 0555 -o root -g wheel "${here}/../deploy/rc.d/cbsdweb" ${PREFIX}/etc/rc.d/cbsdweb

if ! su -m "$USER" -c "$BIN -config ${ETC}/cbsd-web.conf users" | grep -q .; then
	say "creating the first administrator"
	su -m "$USER" -c "$BIN -config ${ETC}/cbsd-web.conf useradd admin -role admin -generate"
	echo "    ^ save this password; change it in the web UI (Учётная запись)."
fi

sysrc -q cbsdweb_enable=YES >/dev/null
service cbsdweb restart

ip=$(ifconfig | awk '/inet / && $2 != "127.0.0.1" {print $2; exit}')
say "done: https://${ip:-<host>}:${LISTEN##*:}/"
if [ ! -f "$(sysrc -n cbsd_workdir 2>/dev/null || echo /usr/jails)/var/db/local.sqlite" ]; then
	echo "    CBSD is not initialised yet: open the UI -> «Установка и настройка» and run the wizard,"
	echo "    then run this installer again so it creates the directory for uploaded ISO images."
fi
