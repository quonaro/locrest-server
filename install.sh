#!/bin/sh
set -e

OWNER="${OWNER:-quonaro}"
REPO="${REPO:-locrest-server}"
VERSION="${VERSION:-latest}"
BIN_NAME="${BIN_NAME:-lrs}"
USER_NAME="${USER_NAME:-locrest}"
GROUP_NAME="${GROUP_NAME:-locrest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/locrest}"
DATA_DIR="${DATA_DIR:-/var/lib/locrest}"
LOG_DIR="${LOG_DIR:-/var/log/locrest}"
CONFIG_FILE="$CONFIG_DIR/locrest.yaml"
SERVICE_NAME="lrs"
INIT_SYSTEM=""
OS=""
ARCH=""
BIN_TMP=""
if [ -t 1 ]; then
	RED='\033[0;31m'
	GREEN='\033[0;32m'
	YELLOW='\033[1;33m'
	BLUE='\033[0;34m'
	NC='\033[0m'
else
	RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

info() { printf "${GREEN}==>${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}WARN:${NC} %s\n" "$*" >&2; }
error() { printf "${RED}ERROR:${NC} %s\n" "$*" >&2; exit 1; }
detect_platform() {
	OS=$(uname -s | tr '[:upper:]' '[:lower:]')
	ARCH=$(uname -m)
	case "$ARCH" in
		x86_64|amd64) ARCH=amd64 ;;
		aarch64|arm64) ARCH=arm64 ;;
		armv7l|armv7) ARCH=arm ;;
		i386|i686) ARCH=386 ;;
		*) error "unsupported architecture: $ARCH" ;;
	esac
	case "$OS" in
		linux|darwin|freebsd) ;;
		*) error "unsupported OS: $OS" ;;
	esac
}

detect_init() {
	if [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then INIT_SYSTEM=systemd
	elif [ -d /etc/runlevels ] || command -v rc-update >/dev/null 2>&1; then INIT_SYSTEM=openrc
	elif [ -d /usr/local/etc/rc.d ] && [ -f /etc/rc.conf ]; then INIT_SYSTEM=freebsd
	elif [ -d /Library/LaunchDaemons ] || command -v launchctl >/dev/null 2>&1; then INIT_SYSTEM=launchd
	elif [ -d /etc/init.d ] || command -v update-rc.d >/dev/null 2>&1 || command -v chkconfig >/dev/null 2>&1; then INIT_SYSTEM=sysv
	else warn "could not detect init system; service will not be installed"; INIT_SYSTEM=unknown
	fi
}

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		error "this script must be run as root"
	fi
}

is_installed() {
	if [ -f "$INSTALL_DIR/$BIN_NAME" ]; then return 0; fi
	case "$INIT_SYSTEM" in
		systemd) [ -f "/etc/systemd/system/$SERVICE_NAME.service" ] && return 0 ;;
		sysv) [ -f "/etc/init.d/$SERVICE_NAME" ] && return 0 ;;
		openrc) [ -f "/etc/init.d/$SERVICE_NAME" ] && return 0 ;;
		freebsd) [ -f "/usr/local/etc/rc.d/${SERVICE_NAME}_" ] && return 0 ;;
		launchd) [ -f "/Library/LaunchDaemons/$SERVICE_NAME.plist" ] && return 0 ;;
	esac
	return 1
}

prompt_reinstall() {
	if [ -n "$FORCE_REINSTALL" ]; then return 0; fi
	local ans
	if [ -t 0 ]; then
		printf "lrs is already installed. Reinstall? [y/N]: "
		read -r ans
	elif [ -e /dev/tty ]; then
		printf "lrs is already installed. Reinstall? [y/N]: " > /dev/tty
		read -r ans < /dev/tty
	else
		warn "already installed; use FORCE_REINSTALL=1 to skip this prompt"
		return 1
	fi
	case "$ans" in
		y|Y|yes|YES) return 0 ;;
		*) return 1 ;;
	esac
}

stop_existing_service() {
	case "$INIT_SYSTEM" in
		systemd) systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true ;;
		sysv) service "$SERVICE_NAME" stop 2>/dev/null || true ;;
		openrc) rc-service "$SERVICE_NAME" stop 2>/dev/null || true ;;
		freebsd) service "${SERVICE_NAME}_" stop 2>/dev/null || true ;;
		launchd) launchctl stop "$SERVICE_NAME" 2>/dev/null || true ;;
	esac
}

remove_existing() {
	stop_existing_service
	info "waiting for service to release binary..."
	local i
	for i in 1 2 3 4 5; do
		if rm -f "$INSTALL_DIR/$BIN_NAME" 2>/dev/null; then break; fi
		sleep 1
	done
	if [ -f "$INSTALL_DIR/$BIN_NAME" ]; then
		error "could not remove existing binary; stop the service manually and retry"
	fi
}

download() {
	local url="$1" file="$2"
	if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$file" "$url"
	elif command -v wget >/dev/null 2>&1; then wget -q -O "$file" "$url"
	else error "curl or wget is required"
	fi
}

try_download() {
	local url="$1" file="$2" errfile="${3:-}"
	if [ -n "$errfile" ]; then
		if download "$url" "$file" 2>"$errfile"; then return 0; fi
	else
		if download "$url" "$file" 2>/dev/null; then return 0; fi
	fi
	rm -f "$file"
	return 1
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'
	fi
}

META_TAG=""
META_COMMIT=""

fetch_release_meta() {
	local api_url="https://api.github.com/repos/$OWNER/$REPO/releases/latest"
	local tmpfile
	tmpfile=$(mktemp)
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -H "Accept: application/vnd.github.v3+json" "$api_url" > "$tmpfile" 2>/dev/null || true
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- --header="Accept: application/vnd.github.v3+json" "$api_url" > "$tmpfile" 2>/dev/null || true
	fi
	if [ -s "$tmpfile" ]; then
		META_TAG=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmpfile" | head -n 1)
		META_COMMIT=$(sed -n 's/.*"target_commitish": *"\([^"]*\)".*/\1/p' "$tmpfile" | head -n 1)
	fi
	rm -f "$tmpfile"
}

download_binary() {
	if [ "$VERSION" = "latest" ]; then
		VERSION="${META_TAG:-latest}"
		[ -z "$META_TAG" ] && error "could not determine latest release version"
	fi
	local base_url="https://github.com/$OWNER/$REPO/releases/download/$VERSION"
	local tmp_dir asset candidate err
	tmp_dir=$(mktemp -d)
	asset="$BIN_NAME-$OS-$ARCH"
	err="$tmp_dir/download.err"
	info "downloading $asset"
	if try_download "$base_url/$asset" "$tmp_dir/$asset" "$err"; then BIN_TMP="$tmp_dir/$asset"
	elif try_download "$base_url/$asset.tar.gz" "$tmp_dir/$asset.tar.gz" "$err"; then
		tar -xzf "$tmp_dir/$asset.tar.gz" -C "$tmp_dir"
		candidate=$(find "$tmp_dir" -maxdepth 2 -type f -name "$BIN_NAME" | head -n 1)
		[ -z "$candidate" ] && error "archive did not contain $BIN_NAME"
		BIN_TMP="$candidate"
	elif try_download "$base_url/${BIN_NAME}_${OS}_${ARCH}.tar.gz" "$tmp_dir/alt.tar.gz" "$err"; then
		tar -xzf "$tmp_dir/alt.tar.gz" -C "$tmp_dir"
		candidate=$(find "$tmp_dir" -maxdepth 2 -type f -name "$BIN_NAME" | head -n 1)
		[ -z "$candidate" ] && error "archive did not contain $BIN_NAME"
		BIN_TMP="$candidate"
	else
		printf '%s\n' "tried:" "$base_url/$asset" "$base_url/$asset.tar.gz" "$base_url/${BIN_NAME}_${OS}_${ARCH}.tar.gz" >&2
		error "could not find release asset for $OS/$ARCH ($(cat "$err"))"
	fi
	if try_download "$base_url/$(basename "$BIN_TMP").sha256" "$tmp_dir/checksum"; then
		local expected actual
		expected=$(awk '{print $1}' "$tmp_dir/checksum")
		actual=$(sha256_file "$BIN_TMP")
		if [ "$actual" != "$expected" ]; then
			warn "expected: $expected"
			warn "actual:   $actual"
			error "checksum mismatch"
		fi
		info "checksum verified"
	else warn "no checksum file found; skipping verification"
	fi
}

create_user() {
	case "$OS" in
	darwin) return 0 ;;
	freebsd)
		pw groupshow "$GROUP_NAME" >/dev/null 2>&1 || pw groupadd "$GROUP_NAME"
		id "$USER_NAME" >/dev/null 2>&1 || pw useradd -n "$USER_NAME" -g "$GROUP_NAME" -d "$DATA_DIR" -s /nonexistent -c "Locrest server"
		return 0 ;;
	esac
	if ! grep -q "^$GROUP_NAME:" /etc/group 2>/dev/null; then
		if command -v groupadd >/dev/null 2>&1; then groupadd --system "$GROUP_NAME"
		elif command -v addgroup >/dev/null 2>&1; then addgroup -S "$GROUP_NAME"
		else error "could not create group $GROUP_NAME"
		fi
	fi
	if ! id "$USER_NAME" >/dev/null 2>&1; then
		if command -v useradd >/dev/null 2>&1; then useradd --system --no-create-home --home-dir "$DATA_DIR" -g "$GROUP_NAME" "$USER_NAME"
		elif command -v adduser >/dev/null 2>&1; then adduser -S -D -H -h "$DATA_DIR" -G "$GROUP_NAME" "$USER_NAME"
		else error "could not create user $USER_NAME"
		fi
	fi
}

install_files() {
	info "installing binary to $INSTALL_DIR"
	mkdir -p "$INSTALL_DIR"
	rm -f "$INSTALL_DIR/$BIN_NAME"
	cp "$BIN_TMP" "$INSTALL_DIR/$BIN_NAME"
	chmod 755 "$INSTALL_DIR/$BIN_NAME"
	mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
	chmod 750 "$CONFIG_DIR" "$DATA_DIR"
	chmod 755 "$LOG_DIR"
	chown root:"$GROUP_NAME" "$CONFIG_DIR"
	chown "$USER_NAME":"$GROUP_NAME" "$DATA_DIR" "$LOG_DIR"
}

setup_config() {
	if [ ! -f "$CONFIG_FILE" ]; then
		info "creating default config at $CONFIG_FILE"
		"$INSTALL_DIR/$BIN_NAME" init "$CONFIG_FILE"
	else info "keeping existing config at $CONFIG_FILE"
	fi
	sed -i.bak -E \
		-e "s|^( *)db_path:.*|\1db_path: $DATA_DIR/locrest.db|" \
		"$CONFIG_FILE"
	rm -f "$CONFIG_FILE.bak"
	chown root:"$GROUP_NAME" "$CONFIG_FILE"
	chmod 640 "$CONFIG_FILE"
}

install_systemd() {
	info "installing systemd service"
	cat > "/etc/systemd/system/$SERVICE_NAME.service" <<'UNIT'
[Unit]
Description=Locrest Server
After=network.target
[Service]
Type=simple
User=__USER__
Group=__GROUP__
WorkingDirectory=__DATA_DIR__
Environment=LOCREST_CONFIG=__CONFIG_FILE__
Environment=LOCREST_LOG_DIR=__LOG_DIR__
Environment=LOCREST_ADMIN_SOCKET=__DATA_DIR__/locrest-admin.sock
Environment=PATH=__INSTALL_DIR__:/usr/bin:/bin
ExecStart=__INSTALL_DIR__/lrs run
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
UNIT
	sed -i.bak -e "s|__USER__|$USER_NAME|g" -e "s|__GROUP__|$GROUP_NAME|g" -e "s|__DATA_DIR__|$DATA_DIR|g" -e "s|__CONFIG_FILE__|$CONFIG_FILE|g" -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" -e "s|__LOG_DIR__|$LOG_DIR|g" "/etc/systemd/system/$SERVICE_NAME.service"
	rm -f "/etc/systemd/system/$SERVICE_NAME.service.bak"
	chmod 644 "/etc/systemd/system/$SERVICE_NAME.service"
}

install_sysv() {
	info "installing SysV init script"
	cat > "/etc/init.d/$SERVICE_NAME" <<'INIT'
#!/bin/sh
### BEGIN INIT INFO
# Provides: lrs
# Required-Start: $network $remote_fs
# Required-Stop: $network $remote_fs
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Locrest Server
### END INIT INFO
DAEMON=__INSTALL_DIR__/lrs
PIDFILE=/var/run/lrs.pid
export LOCREST_CONFIG=__CONFIG_FILE__
export LOCREST_ADMIN_SOCKET=__DATA_DIR__/locrest-admin.sock
start(){ cd __DATA_DIR__ || exit 1; if command -v start-stop-daemon >/dev/null 2>&1; then start-stop-daemon --start --quiet --make-pidfile --pidfile $PIDFILE --background --exec $DAEMON -- run; else nohup $DAEMON run >__LOG_DIR__/lrs.log 2>&1 & echo $! > $PIDFILE; fi; }
stop(){ [ -f $PIDFILE ] && kill $(cat $PIDFILE) 2>/dev/null || true; rm -f $PIDFILE; }
case "$1" in start) start;; stop) stop;; restart) stop; sleep 1; start;; status) [ -f $PIDFILE ] && kill -0 $(cat $PIDFILE) 2>/dev/null && echo running || echo not running;; *) echo "Usage: $0 {start|stop|restart|status}"; exit 1;; esac
INIT
	sed -i.bak -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" -e "s|__CONFIG_FILE__|$CONFIG_FILE|g" -e "s|__DATA_DIR__|$DATA_DIR|g" -e "s|__LOG_DIR__|$LOG_DIR|g" "/etc/init.d/$SERVICE_NAME"
	rm -f "/etc/init.d/$SERVICE_NAME.bak"
	chmod 755 "/etc/init.d/$SERVICE_NAME"
}

install_openrc() {
	info "installing OpenRC service"
	cat > "/etc/init.d/$SERVICE_NAME" <<'RC'
#!/sbin/openrc-run
command="__INSTALL_DIR__/lrs"
command_args="run"
command_user="__USER__:__GROUP__"
command_background=true
pidfile="/var/run/lrs.pid"
export LOCREST_CONFIG="__CONFIG_FILE__"
export LOCREST_ADMIN_SOCKET="__DATA_DIR__/locrest-admin.sock"
directory="__DATA_DIR__"
RC
	sed -i.bak -e "s|__USER__|$USER_NAME|g" -e "s|__GROUP__|$GROUP_NAME|g" -e "s|__DATA_DIR__|$DATA_DIR|g" -e "s|__CONFIG_FILE__|$CONFIG_FILE|g" -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" "/etc/init.d/$SERVICE_NAME"
	rm -f "/etc/init.d/$SERVICE_NAME.bak"
	chmod 755 "/etc/init.d/$SERVICE_NAME"
}

install_freebsd() {
	info "installing FreeBSD rc.d script"
	cat > "/usr/local/etc/rc.d/${SERVICE_NAME}_" <<'BSD'
#!/bin/sh
# PROVIDE: locrest_server
# REQUIRE: NETWORKING
# KEYWORD: shutdown
. /etc/rc.subr
name="lrs"
rcvar="lrs_enable"
pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
command_args="-p ${pidfile} -u __USER__ -r __INSTALL_DIR__/lrs run"
lrs_env="LOCREST_CONFIG=__CONFIG_FILE__ LOCREST_ADMIN_SOCKET=__DATA_DIR__/locrest-admin.sock LOCREST_LOG_DIR=__LOG_DIR__"
load_rc_config $name
run_rc_command "$1"
BSD
	sed -i.bak -e "s|__USER__|$USER_NAME|g" -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" -e "s|__CONFIG_FILE__|$CONFIG_FILE|g" -e "s|__LOG_DIR__|$LOG_DIR|g" "/usr/local/etc/rc.d/${SERVICE_NAME}_"
	rm -f "/usr/local/etc/rc.d/${SERVICE_NAME}_.bak"
	chmod 755 "/usr/local/etc/rc.d/${SERVICE_NAME}_"
}

install_launchd() {
	info "installing launchd plist"
	cat > "/Library/LaunchDaemons/$SERVICE_NAME.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>lrs</string>
<key>ProgramArguments</key><array><string>__INSTALL_DIR__/lrs</string><string>run</string></array>
<key>EnvironmentVariables</key><dict><key>LOCREST_CONFIG</key><string>__CONFIG_FILE__</string><key>LOCREST_ADMIN_SOCKET</key><string>__DATA_DIR__/locrest-admin.sock</string></dict>
<key>WorkingDirectory</key><string>__DATA_DIR__</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>__LOG_DIR__/lrs.log</string>
<key>StandardErrorPath</key><string>__LOG_DIR__/lrs.log</string>
</dict></plist>
PLIST
	sed -i.bak -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" -e "s|__CONFIG_FILE__|$CONFIG_FILE|g" -e "s|__DATA_DIR__|$DATA_DIR|g" -e "s|__LOG_DIR__|$LOG_DIR|g" "/Library/LaunchDaemons/$SERVICE_NAME.plist"
	rm -f "/Library/LaunchDaemons/$SERVICE_NAME.plist.bak"
	chmod 644 "/Library/LaunchDaemons/$SERVICE_NAME.plist"
}

install_service() {
	case "$INIT_SYSTEM" in
	systemd) install_systemd ;;
	sysv) install_sysv ;;
	openrc) install_openrc ;;
	freebsd) install_freebsd ;;
	launchd) install_launchd ;;
	*) warn "no service installed" ;;
	esac
}

enable_start_service() {
	case "$INIT_SYSTEM" in
	systemd) systemctl daemon-reload; systemctl enable "$SERVICE_NAME.service"; systemctl start "$SERVICE_NAME.service" ;;
	sysv) if command -v update-rc.d >/dev/null 2>&1; then update-rc.d "$SERVICE_NAME" defaults; elif command -v chkconfig >/dev/null 2>&1; then chkconfig --add "$SERVICE_NAME"; fi; service "$SERVICE_NAME" start ;;
	openrc) rc-update add "$SERVICE_NAME" default; rc-service "$SERVICE_NAME" start ;;
	freebsd) sysrc "${SERVICE_NAME}_enable=YES"; service "${SERVICE_NAME}_" start ;;
	launchd) launchctl load "/Library/LaunchDaemons/$SERVICE_NAME.plist"; launchctl start "$SERVICE_NAME" ;;
	*) warn "service not started" ;;
	esac
}

banner() {
	local ver="$1" commit="$2" plat="$3" init="$4"
	printf "${BLUE}"
	printf '+-----------------------------------+\n'
	printf '|  Locrest Server Installer         |\n'
	printf '+-----------------------------------+\n'
	printf "${NC}\n"
	printf "  %s (%s)  %s  %s\n\n" "$ver" "$commit" "$plat" "$init"
}

main() {
	detect_platform
	detect_init
	if [ "$VERSION" = "latest" ]; then
		fetch_release_meta
		VERSION="${META_TAG:-latest}"
	fi
	banner "$VERSION" "${META_COMMIT:-unknown}" "$OS/$ARCH" "$INIT_SYSTEM"
	require_root
	if is_installed; then
		if prompt_reinstall; then
			info "removing existing installation..."
			remove_existing
		else
			info "installation cancelled"
			exit 0
		fi
	fi
	download_binary
	create_user
	install_files
	setup_config
	install_service
	enable_start_service
	info "installation complete"
	echo "  binary: $INSTALL_DIR/$BIN_NAME"
	echo "  config: $CONFIG_FILE"
	echo "  init:   $INIT_SYSTEM"
	echo "edit $CONFIG_FILE (at least the domain) before exposing the server"
}

main "$@"
