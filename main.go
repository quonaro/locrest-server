package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "embed"

	"locrest-server/internal/cli"

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

func main() {
	configPath, args := parseConfigFlag(os.Args[1:])
	if configPath != "" {
		os.Setenv("LOCREST_CONFIG", configPath)
	}

	if len(args) == 0 {
		if err := cli.StartServer(); err != nil {
			fmt.Fprintf(os.Stderr, "server: %v\n", err)
			os.Exit(1)
		}
		return
	}

	builder := engine.NewBuilder("locrest-server", cliYAML)
	builder.RegisterNative("user.add", cli.UserAdd)
	builder.RegisterNative("user.delete", cli.UserDelete)
	builder.RegisterNative("user.regenerate", cli.UserRegenerate)
	builder.RegisterNative("user.show", cli.UserShow)
	builder.RegisterNative("user.list", cli.UserList)

	app, err := builder.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	if err := app.Run(context.Background(), args); err != nil {
		var groupErr *engine.GroupError
		if errors.As(err, &groupErr) {
			app.PrintGroupHelp(groupErr.Groups)
			return
		}
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		os.Exit(1)
	}
}
