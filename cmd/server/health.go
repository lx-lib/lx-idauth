package main

import (
	"fmt"
	"os"

	"github.com/nobid-lsp-latvia/lx-idauth/app"

	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// healthCmd represents the health command.
var healthCmd = &cobra.Command{
	Use:           "health",
	Short:         "Check health of the server",
	Long:          `Check if the web server is running and responding to healthz request`,
	RunE:          runHealth,
	SilenceErrors: true,
}

func runHealth(cmd *cobra.Command, _ []string) error {
	a, err := app.New(cmd, Version)
	if err != nil {
		a.Log().Error("failed to load configuration", zap.Error(err))
		os.Exit(1)

		return nil
	}

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod(fasthttp.MethodGet)

	req.SetRequestURI(fmt.Sprintf("http://localhost:%d%s/healthz", a.Config().Server.HTTP.Port, a.RouterOptions().BasePath))

	resp := fasthttp.AcquireResponse()
	client := &fasthttp.Client{}
	err = client.Do(req, resp)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		a.Log().Error("failed to connect to the server", zap.Error(err))
		fasthttp.ReleaseResponse(resp)
		os.Exit(1)

		return nil
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		a.Log().Error("server returned unexpected status code", zap.Int("status", resp.StatusCode()))
		fasthttp.ReleaseResponse(resp)
		os.Exit(1)

		return nil
	}

	a.Log().Info("Service is up and healthy")

	fasthttp.ReleaseResponse(resp)

	return nil
}

func init() {
	initRootCmd()
	RootCmd.AddCommand(healthCmd)
}
