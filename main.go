package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "embed"

	"locrest-server/internal/cli"

	"github.com/fatih/color"
	"github.com/quonaro/lota/engine"
)

//go:embed cli.yml
var cliYAML []byte

func parseConfigFlag(args []string) (string, []string) {
	var configPath string
	var remaining []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-c" || args[i] == "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case strings.HasPrefix(args[i], "--config="):
			configPath = strings.TrimPrefix(args[i], "--config=")
		case strings.HasPrefix(args[i], "-c="):
			configPath = strings.TrimPrefix(args[i], "-c=")
		default:
			remaining = append(remaining, args[i])
		}
	}
	return configPath, remaining
}

var (
	version = "dev"
	commit  = "unknown"
)

func parseGlobalFlags(args []string) (remaining []string, showVersion, showHelp bool) {
	for _, a := range args {
		switch a {
		case "-v", "--version":
			showVersion = true
		case "-h", "--help":
			showHelp = true
		default:
			remaining = append(remaining, a)
		}
	}
	return
}

func buildApp() (*engine.App, error) {
	builder := engine.NewBuilder("lrs", cliYAML)
	builder.RegisterNative("run", cli.StartServer)
	builder.RegisterNative("user.add", cli.UserAdd)
	builder.RegisterNative("user.delete", cli.UserDelete)
	builder.RegisterNative("user.regenerate", cli.UserRegenerate)
	builder.RegisterNative("user.show", cli.UserShow)
	builder.RegisterNative("user.list", cli.UserList)
	builder.RegisterNative("soft-reload", cli.SoftReload)
	return builder.Build()
}

func main() {
	configPath, args := parseConfigFlag(os.Args[1:])
	if configPath != "" {
		_ = os.Setenv("LOCREST_CONFIG", configPath)
	}

	args, showVersion, showHelp := parseGlobalFlags(args)
	if showVersion {
		fmt.Printf("lrs %s (commit %s)\n", version, commit)
		return
	}

	if showHelp {
		app, err := buildApp()
		if err != nil {
			_, _ = color.New(color.FgRed).Fprintf(os.Stderr, "config: %v\n", err)
			os.Exit(1)
		}
		app.PrintGroupHelp(nil)
		return
	}

	app, err := buildApp()
	if err != nil {
		_, _ = color.New(color.FgRed).Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	if len(args) == 0 {
		app.PrintGroupHelp(nil)
		return
	}

	if err := app.Run(context.Background(), args); err != nil {
		var groupErr *engine.GroupError
		if errors.As(err, &groupErr) {
			app.PrintGroupHelp(groupErr.Groups)
			return
		}
		_, _ = color.New(color.FgRed).Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
