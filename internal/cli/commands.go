package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"locrest-server/internal/auth"
	"locrest-server/internal/chiselwrapper"
	"locrest-server/internal/config"
	"locrest-server/internal/db"
	"locrest-server/internal/server"

	"github.com/fatih/color"
	"github.com/quonaro/lota/engine"
	"gopkg.in/yaml.v3"
)

const defaultConfigPath = "locrest.yaml"

func configPath() string {
	if p := os.Getenv("LOCREST_CONFIG"); p != "" {
		return p
	}
	return defaultConfigPath
}

func loadConfig(path string) (*config.ServerConfig, error) {
	cfg := config.DefaultConfig()
	if path == "" {
		path = defaultConfigPath
	}
	loaded, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	*cfg = *loaded
	return cfg, nil
}

func openDB(cfg *config.ServerConfig) (*db.DB, error) {
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	return database, nil
}

// InitConfig writes a default config file to disk.
func InitConfig(ctx context.Context, nctx engine.NativeContext) error {
	path := nctx.Args["path"]
	if path == "" {
		path = defaultConfigPath
	}

	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config file already exists: %s", path)
	}

	cfg := config.DefaultConfig()
	root := struct {
		Server config.ServerConfig `yaml:"server"`
	}{Server: *cfg}

	b, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Fprintf(nctx.Stdout, "Created default config: %s\n", path)
	return nil
}

// RunServer starts the locrest-server.
func RunServer(ctx context.Context, nctx engine.NativeContext) error {
	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}

	initLogLevel(cfg.LogLevel)

	database, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	store := auth.NewStore(database)
	chisel, err := chiselwrapper.New()
	if err != nil {
		return fmt.Errorf("chisel init: %w", err)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	database.StartCleaner(ctx, 30*time.Second)

	frontend := server.NewFrontend(cfg, store, chisel, database)
	frontend.ReloadChiselUsers()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutting down")
		stop()
	}()

	slog.Info("locrest-server starting", "http_port", cfg.HTTPPort, "https_port", cfg.HTTPSPort)
	if err := frontend.Run(ctx); err != nil {
		return fmt.Errorf("frontend run: %w", err)
	}
	return nil
}

func initLogLevel(level string) {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "info":
		lv = slog.LevelInfo
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})))
}

// UserAdd creates a new user with a generated token and seed phrase.
func UserAdd(ctx context.Context, nctx engine.NativeContext) error {
	username := nctx.Args["username"]
	if username == "" {
		return fmt.Errorf("username is required")
	}

	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}

	database, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	if _, err := database.GetUser(username); err == nil {
		return fmt.Errorf("user %q already exists", username)
	}

	apiToken, err := auth.RandString(32)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	seedPhrase, err := auth.GenerateSeedPhrase()
	if err != nil {
		return fmt.Errorf("generate seed phrase: %w", err)
	}

	user := &db.User{
		Username:       username,
		APIToken:       apiToken,
		SeedPhraseHash: db.HashSeedPhrase(seedPhrase),
		CreatedAt:      time.Now().UTC(),
	}
	if err := database.CreateUser(user); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	greenBold := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	magenta := color.New(color.FgMagenta)
	dim := color.New(color.FgHiBlack)

	greenBold.Fprintf(nctx.Stdout, "User created: %s\n\n", username)

	magenta.Fprintln(nctx.Stdout, "Credentials")
	cyan.Fprintf(nctx.Stdout, "  API token:   ")
	yellow.Fprintln(nctx.Stdout, apiToken)
	cyan.Fprintf(nctx.Stdout, "  Seed phrase: ")
	yellow.Fprintln(nctx.Stdout, seedPhrase)
	dim.Fprintln(nctx.Stdout, "  Save these values. The seed phrase is the only way to recover a lost token.")

	fmt.Fprintln(nctx.Stdout)
	magenta.Fprintln(nctx.Stdout, "Usage")
	cyan.Fprintf(nctx.Stdout, "  Create an authenticated tunnel")
	fmt.Fprintf(nctx.Stdout, " (replace 8080 with your local port):\n")
	dim.Fprintf(nctx.Stdout, "    curl -H \"Authorization: Bearer %s\" https://%s/8080?infinity=true | bash\n", apiToken, cfg.Domain)

	fmt.Fprintln(nctx.Stdout)
	cyan.Fprintln(nctx.Stdout, "  Regenerate a lost API token using the seed phrase:")
	dim.Fprintf(nctx.Stdout, "    curl -X POST -H \"Content-Type: application/json\" -d '{\"seed_phrase\":\"%s\"}' https://%s/regenerate\n", seedPhrase, cfg.Domain)

	fmt.Fprintln(nctx.Stdout)
	dim.Fprintln(nctx.Stdout, "Note: the client binary does not use the API token directly.")
	dim.Fprintln(nctx.Stdout, "      The script above passes a temporary setup-token to the client automatically.")
	return nil
}

// UserDelete removes a user.
func UserDelete(ctx context.Context, nctx engine.NativeContext) error {
	username := nctx.Args["username"]
	if username == "" {
		return fmt.Errorf("username is required")
	}

	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}

	database, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	if _, err := database.GetUser(username); err != nil {
		return fmt.Errorf("user %q not found", username)
	}

	if err := database.DeleteUser(username); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	color.New(color.FgRed, color.Bold).Fprint(nctx.Stdout, "User deleted: ")
	color.New(color.FgYellow).Fprintln(nctx.Stdout, username)
	return nil
}

// UserRegenerate replaces a user's API token.
func UserRegenerate(ctx context.Context, nctx engine.NativeContext) error {
	username := nctx.Args["username"]
	if username == "" {
		return fmt.Errorf("username is required")
	}

	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}

	database, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	if _, err := database.GetUser(username); err != nil {
		return fmt.Errorf("user %q not found", username)
	}

	newToken, err := auth.RandString(32)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	if err := database.UpdateUserToken(username, newToken); err != nil {
		return fmt.Errorf("update token: %w", err)
	}

	greenBold := color.New(color.FgGreen, color.Bold)
	greenBold.Fprintf(nctx.Stdout, "Token regenerated for ")
	color.New(color.FgYellow).Fprintln(nctx.Stdout, username)
	color.New(color.FgCyan).Fprint(nctx.Stdout, "New API token: ")
	color.New(color.FgYellow).Fprintln(nctx.Stdout, newToken)
	return nil
}

// UserShow prints a single user.
func UserShow(ctx context.Context, nctx engine.NativeContext) error {
	username := nctx.Args["username"]
	if username == "" {
		return fmt.Errorf("username is required")
	}

	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}

	database, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	user, err := database.GetUser(username)
	if err != nil {
		return fmt.Errorf("user %q not found", username)
	}

	printUser(nctx, user)
	return nil
}

// UserList prints all users.
func UserList(ctx context.Context, nctx engine.NativeContext) error {
	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}

	database, err := openDB(cfg)
	if err != nil {
		return err
	}
	defer database.Close()

	users, err := database.ListUsers()
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	if len(users) == 0 {
		color.New(color.FgHiBlack).Fprintln(nctx.Stdout, "No users")
		return nil
	}

	for _, user := range users {
		printUser(nctx, user)
	}
	return nil
}

func printUser(nctx engine.NativeContext, user *db.User) {
	color.New(color.FgCyan).Fprint(nctx.Stdout, "username: ")
	color.New(color.FgYellow).Fprintln(nctx.Stdout, user.Username)
	color.New(color.FgCyan).Fprint(nctx.Stdout, "  api_token:  ")
	color.New(color.FgYellow).Fprintln(nctx.Stdout, user.APIToken)
	color.New(color.FgHiBlack).Fprintf(nctx.Stdout, "  created_at: %s\n", user.CreatedAt.Format(time.RFC3339))
	if !user.Expire.IsZero() {
		color.New(color.FgHiBlack).Fprintf(nctx.Stdout, "  expire:     %s\n", user.Expire.Format(time.RFC3339))
	}
	fmt.Fprintln(nctx.Stdout)
}
