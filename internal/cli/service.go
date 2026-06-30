package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"locrest-server/internal/config"

	"github.com/fatih/color"
	"github.com/quonaro/lota/engine"
	"gopkg.in/yaml.v3"
)

const svcName = "locrest-server"
const installDir = "/usr/local/bin"
const configDir = "/etc/locrest"
const dataDir = "/var/lib/locrest"
const logDir = "/var/log/locrest"
const svcUser = "locrest"
const svcGroup = "locrest"

func detectInit() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return "systemd"
	}
	if _, err := os.Stat("/etc/runlevels"); err == nil {
		return "openrc"
	}
	if _, err := exec.LookPath("rc-update"); err == nil {
		return "openrc"
	}
	if runtime.GOOS == "darwin" {
		return "launchd"
	}
	if runtime.GOOS == "freebsd" {
		return "freebsd"
	}
	if _, err := os.Stat("/etc/init.d"); err == nil {
		return "sysv"
	}
	return "unknown"
}

func requireRoot() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func createDirs() error {
	if err := os.MkdirAll(configDir, 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}
	return nil
}

func createSystemUser() error {
	if runtime.GOOS == "darwin" {
		return nil
	}
	_, err := user.LookupGroup(svcGroup)
	if err != nil {
		if _, err := exec.LookPath("groupadd"); err == nil {
			_ = runCmd("groupadd", "--system", svcGroup)
		} else if _, err := exec.LookPath("addgroup"); err == nil {
			_ = runCmd("addgroup", "-S", svcGroup)
		}
	}
	_, err = user.Lookup(svcUser)
	if err != nil {
		if _, err := exec.LookPath("useradd"); err == nil {
			return runCmd("useradd", "--system", "--no-create-home", "--home-dir", dataDir, "-g", svcGroup, svcUser)
		}
		if _, err := exec.LookPath("adduser"); err == nil {
			return runCmd("adduser", "-S", "-D", "-H", "-h", dataDir, "-G", svcGroup, svcUser)
		}
	}
	return nil
}

func ensureConfig() error {
	path := configDir + "/locrest.yaml"
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	cfg := config.DefaultConfig()
	cfg.DBPath = dataDir + "/locrest.db"
	cfg.AdminSocketPath = dataDir + "/locrest-admin.sock"
	root := struct {
		Server config.ServerConfig `yaml:"server"`
	}{Server: *cfg}
	b, _ := yaml.Marshal(root)
	if err := os.WriteFile(path, b, 0640); err != nil {
		return err
	}
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return nil
}

func installSystemd() error {
	unit := "[Unit]\nDescription=Locrest Server\nAfter=network.target\n[Service]\nType=simple\nUser=" + svcUser + "\nGroup=" + svcGroup + "\nWorkingDirectory=" + dataDir + "\nEnvironment=LOCREST_CONFIG=" + configDir + "/locrest.yaml\nEnvironment=PATH=" + installDir + ":/usr/bin:/bin\nExecStart=" + installDir + "/locrest-server run\nRestart=on-failure\nRestartSec=5\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n[Install]\nWantedBy=multi-user.target\n"
	return os.WriteFile("/etc/systemd/system/"+svcName+".service", []byte(unit), 0644)
}

func installSysv() error {
	script := "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: locrest-server\n# Required-Start: $network $remote_fs\n# Required-Stop: $network $remote_fs\n# Default-Start: 2 3 4 5\n# Default-Stop: 0 1 6\n# Short-Description: Locrest Server\n### END INIT INFO\nDAEMON=" + installDir + "/locrest-server\nPIDFILE=/var/run/locrest-server.pid\nexport LOCREST_CONFIG=" + configDir + "/locrest.yaml\nstart(){ cd " + dataDir + " || exit 1; if command -v start-stop-daemon >/dev/null 2>&1; then start-stop-daemon --start --quiet --make-pidfile --pidfile $PIDFILE --background --exec $DAEMON -- run; else nohup $DAEMON run >" + logDir + "/locrest-server.log 2>&1 & echo $! > $PIDFILE; fi; }\nstop(){ [ -f $PIDFILE ] && kill $(cat $PIDFILE) 2>/dev/null || true; rm -f $PIDFILE; }\ncase \"$1\" in start) start;; stop) stop;; restart) stop; sleep 1; start;; status) [ -f $PIDFILE ] && kill -0 $(cat $PIDFILE) 2>/dev/null && echo running || echo not running;; *) echo \"Usage: $0 {start|stop|restart|status}\"; exit 1;; esac\n"
	return os.WriteFile("/etc/init.d/"+svcName, []byte(script), 0755)
}

func installOpenRC() error {
	script := "#!/sbin/openrc-run\ncommand=\"" + installDir + "/locrest-server\"\ncommand_args=\"run\"\ncommand_user=\"" + svcUser + ":" + svcGroup + "\"\ncommand_background=true\npidfile=\"/var/run/locrest-server.pid\"\nexport LOCREST_CONFIG=\"" + configDir + "/locrest.yaml\"\ndirectory=\"" + dataDir + "\"\n"
	return os.WriteFile("/etc/init.d/"+svcName, []byte(script), 0755)
}

func installFreeBSD() error {
	script := "#!/bin/sh\n# PROVIDE: locrest_server\n# REQUIRE: NETWORKING\n# KEYWORD: shutdown\n. /etc/rc.subr\nname=\"locrest_server\"\nrcvar=\"locrest_server_enable\"\npidfile=\"/var/run/${name}.pid\"\ncommand=\"/usr/sbin/daemon\"\ncommand_args=\"-p ${pidfile} -u " + svcUser + " -r " + installDir + "/locrest-server run\"\nlocrest_server_env=\"LOCREST_CONFIG=" + configDir + "/locrest.yaml\"\nload_rc_config $name\nrun_rc_command \"$1\"\n"
	return os.WriteFile("/usr/local/etc/rc.d/"+svcName+"_", []byte(script), 0755)
}

func installLaunchd() error {
	plist := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>locrest-server</string>\n<key>ProgramArguments</key><array><string>" + installDir + "/locrest-server</string><string>run</string></array>\n<key>EnvironmentVariables</key><dict><key>LOCREST_CONFIG</key><string>" + configDir + "/locrest.yaml</string></dict>\n<key>WorkingDirectory</key><string>" + dataDir + "</string>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>StandardOutPath</key><string>" + logDir + "/locrest-server.log</string>\n<key>StandardErrorPath</key><string>" + logDir + "/locrest-server.log</string>\n</dict></plist>\n"
	return os.WriteFile("/Library/LaunchDaemons/"+svcName+".plist", []byte(plist), 0644)
}

func installService() error {
	switch detectInit() {
	case "systemd":
		return installSystemd()
	case "sysv":
		return installSysv()
	case "openrc":
		return installOpenRC()
	case "freebsd":
		return installFreeBSD()
	case "launchd":
		return installLaunchd()
	default:
		return fmt.Errorf("unsupported init system")
	}
}

func enableService() error {
	switch detectInit() {
	case "systemd":
		return runCmd("systemctl", "enable", svcName+".service")
	case "sysv":
		if _, err := exec.LookPath("update-rc.d"); err == nil {
			return runCmd("update-rc.d", svcName, "defaults")
		}
		if _, err := exec.LookPath("chkconfig"); err == nil {
			return runCmd("chkconfig", "--add", svcName)
		}
		return nil
	case "openrc":
		return runCmd("rc-update", "add", svcName, "default")
	case "freebsd":
		return runCmd("sysrc", svcName+"_enable=YES")
	case "launchd":
		return runCmd("launchctl", "load", "/Library/LaunchDaemons/"+svcName+".plist")
	default:
		return nil
	}
}

func disableService() error {
	switch detectInit() {
	case "systemd":
		_ = runCmd("systemctl", "disable", svcName+".service")
		return nil
	case "sysv":
		if _, err := exec.LookPath("update-rc.d"); err == nil {
			_ = runCmd("update-rc.d", "-f", svcName, "remove")
		}
		if _, err := exec.LookPath("chkconfig"); err == nil {
			_ = runCmd("chkconfig", "--del", svcName)
		}
		return nil
	case "openrc":
		_ = runCmd("rc-update", "del", svcName, "default")
		return nil
	case "freebsd":
		_ = runCmd("sysrc", "-x", svcName+"_enable")
		return nil
	case "launchd":
		_ = runCmd("launchctl", "unload", "/Library/LaunchDaemons/"+svcName+".plist")
		return nil
	default:
		return nil
	}
}

func startService() error {
	switch detectInit() {
	case "systemd":
		return runCmd("systemctl", "start", svcName+".service")
	case "sysv":
		return runCmd("service", svcName, "start")
	case "openrc":
		return runCmd("rc-service", svcName, "start")
	case "freebsd":
		return runCmd("service", svcName+"_", "start")
	case "launchd":
		return runCmd("launchctl", "start", svcName)
	default:
		return fmt.Errorf("unsupported init system")
	}
}

func stopService() error {
	switch detectInit() {
	case "systemd":
		return runCmd("systemctl", "stop", svcName+".service")
	case "sysv":
		return runCmd("service", svcName, "stop")
	case "openrc":
		return runCmd("rc-service", svcName, "stop")
	case "freebsd":
		return runCmd("service", svcName+"_", "stop")
	case "launchd":
		return runCmd("launchctl", "stop", svcName)
	default:
		return fmt.Errorf("unsupported init system")
	}
}

func restartService() error {
	switch detectInit() {
	case "systemd":
		return runCmd("systemctl", "restart", svcName+".service")
	case "sysv":
		return runCmd("service", svcName, "restart")
	case "openrc":
		return runCmd("rc-service", svcName, "restart")
	case "freebsd":
		return runCmd("service", svcName+"_", "restart")
	case "launchd":
		_ = runCmd("launchctl", "stop", svcName)
		return runCmd("launchctl", "start", svcName)
	default:
		return fmt.Errorf("unsupported init system")
	}
}

func statusService() (string, error) {
	var out []byte
	var err error
	switch detectInit() {
	case "systemd":
		out, err = exec.Command("systemctl", "is-active", svcName+".service").CombinedOutput()
	case "sysv":
		out, err = exec.Command("service", svcName, "status").CombinedOutput()
	case "openrc":
		out, err = exec.Command("rc-service", svcName, "status").CombinedOutput()
	case "freebsd":
		out, err = exec.Command("service", svcName+"_", "status").CombinedOutput()
	case "launchd":
		out, err = exec.Command("launchctl", "list", svcName).CombinedOutput()
	default:
		return "", fmt.Errorf("unsupported init system")
	}
	return strings.TrimSpace(string(out)), err
}

// ServiceInstall installs the system service unit.
func ServiceInstall(ctx context.Context, nctx engine.NativeContext) error {
	if err := requireRoot(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate binary: %w", err)
	}
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("create bin dir: %w", err)
	}
	if err := runCmd("cp", exe, installDir+"/locrest-server"); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := os.Chmod(installDir+"/locrest-server", 0755); err != nil {
		return fmt.Errorf("chmod binary: %w", err)
	}
	if err := createSystemUser(); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	if err := createDirs(); err != nil {
		return fmt.Errorf("create dirs: %w", err)
	}
	if err := ensureConfig(); err != nil {
		return fmt.Errorf("ensure config: %w", err)
	}
	if err := installService(); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	if err := enableService(); err != nil {
		return fmt.Errorf("enable service: %w", err)
	}
	color.New(color.FgGreen, color.Bold).Fprintln(nctx.Stdout, "Service installed and enabled")
	return nil
}

// ServiceUninstall removes the system service unit.
func ServiceUninstall(ctx context.Context, nctx engine.NativeContext) error {
	if err := requireRoot(); err != nil {
		return err
	}
	_ = stopService()
	_ = disableService()
	paths := []string{
		"/etc/systemd/system/" + svcName + ".service",
		"/etc/init.d/" + svcName,
		"/usr/local/etc/rc.d/" + svcName + "_",
		"/Library/LaunchDaemons/" + svcName + ".plist",
	}
	for _, p := range paths {
		_ = os.Remove(p)
	}
	if detectInit() == "systemd" {
		_ = runCmd("systemctl", "daemon-reload")
	}
	color.New(color.FgGreen, color.Bold).Fprintln(nctx.Stdout, "Service uninstalled")
	return nil
}

// ServiceStart starts the service.
func ServiceStart(ctx context.Context, nctx engine.NativeContext) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := startService(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	color.New(color.FgGreen).Fprintln(nctx.Stdout, "Service started")
	return nil
}

// ServiceStop stops the service.
func ServiceStop(ctx context.Context, nctx engine.NativeContext) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := stopService(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	color.New(color.FgGreen).Fprintln(nctx.Stdout, "Service stopped")
	return nil
}

// ServiceRestart restarts the service.
func ServiceRestart(ctx context.Context, nctx engine.NativeContext) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := restartService(); err != nil {
		return fmt.Errorf("restart service: %w", err)
	}
	color.New(color.FgGreen).Fprintln(nctx.Stdout, "Service restarted")
	return nil
}

// ServiceStatus prints the service status.
func ServiceStatus(ctx context.Context, nctx engine.NativeContext) error {
	status, err := statusService()
	if err != nil {
		fmt.Fprintln(nctx.Stdout, status)
		return fmt.Errorf("status failed: %w", err)
	}
	fmt.Fprintln(nctx.Stdout, status)
	return nil
}
