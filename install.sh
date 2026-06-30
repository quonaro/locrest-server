#!/bin/sh
set -e

OWNER="${OWNER:-locrest}"
REPO="${REPO:-locrest}"
VERSION="${VERSION:-latest}"
BIN_NAME="${BIN_NAME:-locrest-server}"
USER_NAME="${USER_NAME:-locrest}"
GROUP_NAME="${GROUP_NAME:-locrest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/locrest}"
DATA_DIR="${DATA_DIR:-/var/lib/locrest}"
LOG_DIR="${LOG_DIR:-/var/log/locrest}"
CONFIG_FILE="$CONFIG_DIR/locrest.yaml"
SERVICE_NAME="locrest-server"
INIT_SYSTEM=""
OS=""
ARCH=""
BIN_TMP=""
info() { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
error() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
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

require_root() { [ "$(id -u)" -ne 0 ] && error "this script must be run as root"; }

download() {
	local url="$1" file="$2"
	if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$file" "$url"
	elif command -v wget >/dev/null 2>&1; then wget -q -O "$file" "$url"
	else error "curl or wget is required"
	fi
}

try_download() {
	local url="$1" file="$2"
	if download "$url" "$file" 2>/dev/null; then return 0; fi
	rm -f "$file"
	return 1
}

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'
	fi
}

download_binary() {
	local base_url="https://github.com/$OWNER/$REPO/releases/download/$VERSION"
	local tmp_dir asset candidate
	tmp_dir=$(mktemp -d)
	asset="$BIN_NAME-$OS-$ARCH"
	info "detected platform: $OS/$ARCH"
	info "downloading from $base_url"
	if try_download "$base_url/$asset" "$tmp_dir/$asset"; then BIN_TMP="$tmp_dir/$asset"
	elif try_download "$base_url/$asset.tar.gz" "$tmp_dir/$asset.tar.gz"; then
		tar -xzf "$tmp_dir/$asset.tar.gz" -C "$tmp_dir"
		candidate=$(find "$tmp_dir" -maxdepth 2 -type f -name "$BIN_NAME" | head -n 1)
		[ -z "$candidate" ] && error "archive did not contain $BIN_NAME"
		BIN_TMP="$candidate"
	elif try_download "$base_url/${BIN_NAME}_${OS}_${ARCH}.tar.gz" "$tmp_dir/alt.tar.gz"; then
		tar -xzf "$tmp_dir/alt.tar.gz" -C "$tmp_dir"
		candidate=$(find "$tmp_dir" -maxdepth 2 -type f -name "$BIN_NAME" | head -n 1)
		[ -z "$candidate" ] && error "archive did not contain $BIN_NAME"
		BIN_TMP="$candidate"
	else error "could not find release asset for $OS/$ARCH"
	fi
	if try_download "$base_url/$(basename "$BIN_TMP").sha256" "$tmp_dir/checksum"; then
		local expected actual
		expected=$(awk '{print $1}' "$tmp_dir/checksum")
		actual=$(sha256_file "$BIN_TMP")
		[ "$actual" != "$expected" ] && error "checksum mismatch"
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
		-e "s|^( *)admin_socket_path:.*|\1admin_socket_path: $DATA_DIR/locrest-admin.sock|" \
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
Environment=PATH=__INSTALL_DIR__:/usr/bin:/bin
ExecStart=__INSTALL_DIR__/locrest-server run
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
UNIT
	sed -i.bak -e "s|__USER__|$USER_NAME|g" -e "s|__GROUP__|$GROUP_NAME|g" -e "s|__DATA_DIR__|$DATA_DIR|g" -e "s|__CONFIG_FILE__|$CONFIG_FILE|g" -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" "/etc/systemd/system/$SERVICE_NAME.service"
	rm -f "/etc/systemd/system/$SERVICE_NAME.service.bak"
	chmod 644 "/etc/systemd/system/$SERVICE_NAME.service"
}

install_sysv() {
	info "installing SysV init script"
	cat > "/etc/init.d/$SERVICE_NAME" <<'INIT'
#!/bin/sh
### BEGIN INIT INFO
# Provides: locrest-server
# Required-Start: $network $remote_fs
# Required-Stop: $network $remote_fs
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Locrest Server
### END INIT INFO
DAEMON=__INSTALL_DIR__/locrest-server
PIDFILE=/var/run/locrest-server.pid
export LOCREST_CONFIG=__CONFIG_FILE__
start(){ cd __DATA_DIR__ || exit 1; if command -v start-stop-daemon >/dev/null 2>&1; then start-stop-daemon --start --quiet --make-pidfile --pidfile $PIDFILE --background --exec $DAEMON -- run; else nohup $DAEMON run >__LOG_DIR__/locrest-server.log 2>&1 & echo $! > $PIDFILE; fi; }
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
command="__INSTALL_DIR__/locrest-server"
command_args="run"
command_user="__USER__:__GROUP__"
command_background=true
pidfile="/var/run/locrest-server.pid"
export LOCREST_CONFIG="__CONFIG_FILE__"
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
name="locrest_server"
rcvar="locrest_server_enable"
pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
command_args="-p ${pidfile} -u __USER__ -r __INSTALL_DIR__/locrest-server run"
locrest_server_env="LOCREST_CONFIG=__CONFIG_FILE__"
load_rc_config $name
run_rc_command "$1"
BSD
	sed -i.bak -e "s|__USER__|$USER_NAME|g" -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" -e "s|__CONFIG_FILE__|$CONFIG_FILE|g" "/usr/local/etc/rc.d/${SERVICE_NAME}_"
	rm -f "/usr/local/etc/rc.d/${SERVICE_NAME}_.bak"
	chmod 755 "/usr/local/etc/rc.d/${SERVICE_NAME}_"
}

install_launchd() {
	info "installing launchd plist"
	cat > "/Library/LaunchDaemons/$SERVICE_NAME.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>locrest-server</string>
<key>ProgramArguments</key><array><string>__INSTALL_DIR__/locrest-server</string><string>run</string></array>
<key>EnvironmentVariables</key><dict><key>LOCREST_CONFIG</key><string>__CONFIG_FILE__</string></dict>
<key>WorkingDirectory</key><string>__DATA_DIR__</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>__LOG_DIR__/locrest-server.log</string>
<key>StandardErrorPath</key><string>__LOG_DIR__/locrest-server.log</string>
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

main() {
	detect_platform
	detect_init
	require_root
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
