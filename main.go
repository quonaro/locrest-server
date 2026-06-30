package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	_ "embed"

	"locrest-server/internal/cli"

	"github.com/quonaro/lota/engine"
)

//go:embed cli.yml
var cliYAML []byte

func main() {
	builder := engine.NewBuilder("locrest-server", cliYAML)
	builder.RegisterNative("init", cli.InitConfig)
	builder.RegisterNative("run", cli.RunServer)
	builder.RegisterNative("add", cli.UserAdd)
	builder.RegisterNative("delete", cli.UserDelete)
	builder.RegisterNative("regenerate", cli.UserRegenerate)
	builder.RegisterNative("show", cli.UserShow)
	builder.RegisterNative("list", cli.UserList)

	app, err := builder.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		app.PrintHelp()
		return
	}

	if err := app.Run(context.Background(), os.Args[1:]); err != nil {
		var groupErr *engine.GroupError
		if errors.As(err, &groupErr) {
			app.PrintGroupHelp(groupErr.Groups)
			return
		}
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		os.Exit(1)
	}
}
