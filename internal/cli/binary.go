package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
	"github.com/quonaro/lota/engine"
)

// BinaryList prints cached client binaries.
func BinaryList(ctx context.Context, nctx engine.NativeContext) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/binaries", nil)
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
		Name      string    `json:"name"`
		Size      int64     `json:"size"`
		ModTime   time.Time `json:"mod_time"`
		SHA256    string    `json:"sha256"`
		SHA256URL string    `json:"sha256_url"`
		Version   string    `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if len(result) == 0 {
		_, _ = color.New(color.FgHiBlack).Fprintln(nctx.Stdout, "No cached binaries")
		return nil
	}

	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.FgHiBlack)
	for _, f := range result {
		_, _ = cyan.Fprint(nctx.Stdout, "name: ")
		_, _ = yellow.Fprintln(nctx.Stdout, f.Name)
		_, _ = dim.Fprintf(nctx.Stdout, "  size:   %d bytes\n", f.Size)
		_, _ = dim.Fprintf(nctx.Stdout, "  mod:    %s\n", f.ModTime.Format(time.RFC3339))
		_, _ = dim.Fprintf(nctx.Stdout, "  sha256: %s\n", f.SHA256)
		_, _ = dim.Fprintf(nctx.Stdout, "  version: %s\n", f.Version)
		_, _ = fmt.Fprintln(nctx.Stdout)
	}
	return nil
}

// BinaryUpdate triggers an immediate binary cache refresh.
func BinaryUpdate(ctx context.Context, nctx engine.NativeContext) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/binaries/update", nil)
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

	if resp.StatusCode != http.StatusNoContent {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin request failed: %s: %s", resp.Status, string(data))
	}

	_, _ = color.New(color.FgGreen, color.Bold).Fprintln(nctx.Stdout, "Binary cache updated successfully")
	return nil
}
