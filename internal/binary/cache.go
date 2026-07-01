package binary

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var defaultPlatforms = []string{
	"linux-amd64",
	"linux-arm64",
	"darwin-amd64",
	"darwin-arm64",
	"windows-amd64",
}

// FileInfo describes a cached binary.
type FileInfo struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	SHA256    string    `json:"sha256"`
	SHA256URL string    `json:"sha256_url"`
}

// Cache manages downloaded client binaries.
type Cache struct {
	dir       string
	binaryURL string
	platforms []string
}

// NewCache creates a cache that stores binaries in dir, downloaded from binaryURL.
func NewCache(dir, binaryURL string) *Cache {
	return &Cache{
		dir:       dir,
		binaryURL: strings.TrimRight(binaryURL, "/"),
		platforms: defaultPlatforms,
	}
}

// Dir returns the cache directory.
func (c *Cache) Dir() string { return c.dir }

// Update downloads all platform binaries and their checksums, validates every
// SHA-256, and atomically replaces the cache directory. If any checksum fails,
// the entire update is aborted and no existing files are touched.
func (c *Cache) Update(ctx context.Context) error {
	tmpDir, err := os.MkdirTemp(filepath.Dir(c.dir), "bin-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	client := &http.Client{Timeout: 60 * time.Second}

	for _, plat := range c.platforms {
		binName := "lrc-" + plat
		if err := c.downloadPair(ctx, client, tmpDir, binName); err != nil {
			return fmt.Errorf("download %s: %w", binName, err)
		}
	}

	// Verify every checksum before moving anything into place.
	for _, plat := range c.platforms {
		binName := "lrc-" + plat
		if err := verifyFile(filepath.Join(tmpDir, binName), filepath.Join(tmpDir, binName+".sha256")); err != nil {
			return fmt.Errorf("verify %s: %w", binName, err)
		}
	}

	// Atomic swap: rename old dir out, rename temp in, remove old.
	oldDir := c.dir + ".old"
	_ = os.RemoveAll(oldDir)
	if _, err := os.Stat(c.dir); err == nil {
		if err := os.Rename(c.dir, oldDir); err != nil {
			return fmt.Errorf("rename old dir: %w", err)
		}
	}
	if err := os.Rename(tmpDir, c.dir); err != nil {
		// Try to restore old dir on failure.
		_ = os.Rename(oldDir, c.dir)
		return fmt.Errorf("rename temp dir: %w", err)
	}
	_ = os.RemoveAll(oldDir)

	slog.Info("binary cache updated", "dir", c.dir, "platforms", len(c.platforms))
	return nil
}

func (c *Cache) downloadPair(ctx context.Context, client *http.Client, tmpDir, binName string) error {
	binURL := c.binaryURL + "/" + binName
	if err := downloadFile(ctx, client, binURL, filepath.Join(tmpDir, binName)); err != nil {
		return err
	}
	shaURL := binURL + ".sha256"
	if err := downloadFile(ctx, client, shaURL, filepath.Join(tmpDir, binName+".sha256")); err != nil {
		return err
	}
	return nil
}

// List returns metadata for every cached binary.
func (c *Cache) List() ([]FileInfo, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache dir: %w", err)
	}

	var result []FileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "lrc-") || strings.HasSuffix(entry.Name(), ".sha256") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		fi := FileInfo{
			Name:      entry.Name(),
			Size:      info.Size(),
			ModTime:   info.ModTime(),
			SHA256URL: c.binaryURL + "/" + entry.Name() + ".sha256",
		}
		if sum, err := readSHA256File(filepath.Join(c.dir, entry.Name()+".sha256")); err == nil {
			fi.SHA256 = sum
		}
		result = append(result, fi)
	}
	return result, nil
}
