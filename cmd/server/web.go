package main

import (
	"github.com/nobid-lsp-latvia/lx-idauth/app"

	"azugo.io/core/server"
	"github.com/spf13/cobra"
)

var configPath string

// webCmd represents the web command.
var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start web server",
	Long: `Web server is the only thing you need to run,
and it takes care of all the other things for you`,
	RunE: runWeb,
}

func runWeb(cmd *cobra.Command, _ []string) error {
	a, err := app.New(cmd, Version)
	if err != nil {
		return err
	}

	if err = a.Auth().Init(); err != nil {
		return err
	}

	if err = app.Bind(a, a); err != nil {
		return err
	}

	server.Run(a)

	return nil
}

func init() {
	initRootCmd()
	RootCmd.AddCommand(webCmd)

	webCmd.Flags().StringVarP(&configPath,
		"config",
		"c",
		"",
		"Configuration file path")
}
