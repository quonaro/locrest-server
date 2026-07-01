package logger

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"
)

var writer io.Writer

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func envString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func newHandler(level string) *slog.Logger {
	return slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: parseLevel(level)}))
}

// Setup initialises the global logger with file rotation.
// All settings are read from ENV only:
//
//	LOCREST_LOG_DIR         default: "log"
//	LOCREST_LOG_MAX_SIZE_MB default: 100
//	LOCREST_LOG_MAX_AGE_DAYS default: 7
//	LOCREST_LOG_MAX_BACKUPS  default: 10
func Setup(level string) {
	dir := envString("LOCREST_LOG_DIR", "log")
	_ = os.MkdirAll(dir, 0o750)

	logFile := filepath.Join(dir, "locrest-server.log")

	fileWriter := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    envInt("LOCREST_LOG_MAX_SIZE_MB", 100),
		MaxAge:     envInt("LOCREST_LOG_MAX_AGE_DAYS", 7),
		MaxBackups: envInt("LOCREST_LOG_MAX_BACKUPS", 10),
		LocalTime:  true,
		Compress:   true,
	}

	writer = io.MultiWriter(os.Stdout, fileWriter)

	slog.SetDefault(newHandler(level))
}

// ReloadLevel recreates the global logger with a new level while keeping the
// same underlying rotated writer.
func ReloadLevel(level string) {
	if writer == nil {
		Setup(level)
		return
	}
	slog.SetDefault(newHandler(level))
}
