package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
	"github.com/quonaro/lota/engine"
)

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

	body, _ := json.Marshal(map[string]string{"username": username})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/users", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := checkAdminSocket(adminSocketPath()); err != nil {
		return err
	}
	client := adminClient(adminSocketPath())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("user %q already exists", username)
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin request failed: %s: %s", resp.Status, string(data))
	}

	var result struct {
		Username   string    `json:"username"`
		APIToken   string    `json:"api_token"`
		SeedPhrase string    `json:"seed_phrase"`
		CreatedAt  time.Time `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	greenBold := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	magenta := color.New(color.FgMagenta)
	dim := color.New(color.FgHiBlack)

	_, _ = greenBold.Fprintf(nctx.Stdout, "User created: %s\n\n", result.Username)

	_, _ = magenta.Fprintln(nctx.Stdout, "Credentials")
	_, _ = cyan.Fprintf(nctx.Stdout, "  API token:   ")
	_, _ = yellow.Fprintln(nctx.Stdout, result.APIToken)
	_, _ = cyan.Fprintf(nctx.Stdout, "  Seed phrase: ")
	_, _ = yellow.Fprintln(nctx.Stdout, result.SeedPhrase)
	_, _ = dim.Fprintln(nctx.Stdout, "  Save these values. The seed phrase is the only way to recover a lost token.")

	_, _ = fmt.Fprintln(nctx.Stdout)
	_, _ = magenta.Fprintln(nctx.Stdout, "Usage")
	_, _ = cyan.Fprintf(nctx.Stdout, "  Create an authenticated tunnel")
	_, _ = fmt.Fprintf(nctx.Stdout, " (replace 8080 with your local port):\n")
	_, _ = dim.Fprintf(nctx.Stdout, "    curl --oauth2-bearer %s \"https://%s/8080?infinity=true\" | bash\n", result.APIToken, cfg.Network.Domain)
	_, _ = cyan.Fprintf(nctx.Stdout, "  Create a raw TCP/UDP tunnel")
	_, _ = fmt.Fprintf(nctx.Stdout, " (replace 8080 with your local port):\n")
	_, _ = dim.Fprintf(nctx.Stdout, "    curl --oauth2-bearer %s \"https://%s/8080?external_port=8080\" | bash\n", result.APIToken, cfg.Network.Domain)

	_, _ = fmt.Fprintln(nctx.Stdout)
	_, _ = cyan.Fprintln(nctx.Stdout, "  Regenerate a lost API token using the seed phrase:")
	_, _ = dim.Fprintf(nctx.Stdout, "    curl -X POST -H \"Content-Type: application/json\" -d '{\"seed_phrase\":\"%s\"}' https://%s/regenerate\n", result.SeedPhrase, cfg.Network.Domain)

	_, _ = fmt.Fprintln(nctx.Stdout)
	_, _ = dim.Fprintln(nctx.Stdout, "Note: the client binary does not use the API token directly.")
	_, _ = dim.Fprintln(nctx.Stdout, "      The script above passes a temporary setup-token to the client automatically.")
	return nil
}

// UserDelete removes a user.
func UserDelete(ctx context.Context, nctx engine.NativeContext) error {
	username := nctx.Args["username"]
	if username == "" {
		return fmt.Errorf("username is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, fmt.Sprintf("http://unix/users/%s", username), nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	if err := checkAdminSocket(adminSocketPath()); err != nil {
		return err
	}
	client := adminClient(adminSocketPath())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user %q not found", username)
	}
	if resp.StatusCode != http.StatusNoContent {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin request failed: %s: %s", resp.Status, string(data))
	}

	_, _ = color.New(color.FgRed, color.Bold).Fprint(nctx.Stdout, "User deleted: ")
	_, _ = color.New(color.FgYellow).Fprintln(nctx.Stdout, username)
	return nil
}

// UserRegenerate replaces a user's API token.
func UserRegenerate(ctx context.Context, nctx engine.NativeContext) error {
	username := nctx.Args["username"]
	if username == "" {
		return fmt.Errorf("username is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://unix/users/%s/regenerate", username), nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	if err := checkAdminSocket(adminSocketPath()); err != nil {
		return err
	}
	client := adminClient(adminSocketPath())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user %q not found", username)
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin request failed: %s: %s", resp.Status, string(data))
	}

	var result struct {
		APIToken string `json:"api_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	greenBold := color.New(color.FgGreen, color.Bold)
	_, _ = greenBold.Fprintf(nctx.Stdout, "Token regenerated for ")
	_, _ = color.New(color.FgYellow).Fprintln(nctx.Stdout, username)
	_, _ = color.New(color.FgCyan).Fprint(nctx.Stdout, "New API token: ")
	_, _ = color.New(color.FgYellow).Fprintln(nctx.Stdout, result.APIToken)
	return nil
}

// UserShow prints a single user.
func UserShow(ctx context.Context, nctx engine.NativeContext) error {
	username := nctx.Args["username"]
	if username == "" {
		return fmt.Errorf("username is required")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://unix/users/%s", username), nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	if err := checkAdminSocket(adminSocketPath()); err != nil {
		return err
	}
	client := adminClient(adminSocketPath())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("user %q not found", username)
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin request failed: %s: %s", resp.Status, string(data))
	}

	var result struct {
		Username       string    `json:"username"`
		APIToken       string    `json:"api_token"`
		SeedPhraseHash string    `json:"seed_phrase_hash"`
		CreatedAt      time.Time `json:"created_at"`
		Expire         time.Time `json:"expire"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	printUser(nctx, result.Username, result.APIToken, result.CreatedAt, result.Expire)
	return nil
}

// UserList prints all users.
func UserList(ctx context.Context, nctx engine.NativeContext) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/users", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	if err := checkAdminSocket(adminSocketPath()); err != nil {
		return err
	}
	client := adminClient(adminSocketPath())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("admin request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin request failed: %s: %s", resp.Status, string(data))
	}

	var result []struct {
		Username       string    `json:"username"`
		APIToken       string    `json:"api_token"`
		SeedPhraseHash string    `json:"seed_phrase_hash"`
		CreatedAt      time.Time `json:"created_at"`
		Expire         time.Time `json:"expire"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if len(result) == 0 {
		_, _ = color.New(color.FgHiBlack).Fprintln(nctx.Stdout, "No users")
		return nil
	}

	for _, u := range result {
		printUser(nctx, u.Username, u.APIToken, u.CreatedAt, u.Expire)
	}
	return nil
}

func printUser(nctx engine.NativeContext, username, apiToken string, createdAt, expire time.Time) {
	_, _ = color.New(color.FgCyan).Fprint(nctx.Stdout, "username: ")
	_, _ = color.New(color.FgYellow).Fprintln(nctx.Stdout, username)
	_, _ = color.New(color.FgCyan).Fprint(nctx.Stdout, "  api_token:  ")
	_, _ = color.New(color.FgYellow).Fprintln(nctx.Stdout, apiToken)
	_, _ = color.New(color.FgHiBlack).Fprintf(nctx.Stdout, "  created_at: %s\n", createdAt.Format(time.RFC3339))
	if !expire.IsZero() {
		_, _ = color.New(color.FgHiBlack).Fprintf(nctx.Stdout, "  expire:     %s\n", expire.Format(time.RFC3339))
	}
	_, _ = fmt.Fprintln(nctx.Stdout)
}
