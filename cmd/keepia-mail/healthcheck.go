package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keepia/mail/internal/config"
)

// healthcheckTimeout bounds the whole health request.
const healthcheckTimeout = 5 * time.Second

// newHealthcheckCmd is the container's health probe (the image has no
// curl): it asks the local serve's /healthz and exits 0 on 200, 1
// otherwise. It needs no database URL.
func newHealthcheckCmd() *cobra.Command {
	var listen string
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Ask the local serve's /healthz; exit 0 when it answers 200",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			addr := config.Load(os.Getenv).Listen
			if cmd.Flags().Changed("listen") {
				addr = listen
			}
			u, err := healthURL(addr)
			if err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, u, nil)
			if err != nil {
				return err
			}
			// No proxy: the probe goes to this host's serve directly.
			client := &http.Client{Timeout: healthcheckTimeout, Transport: &http.Transport{Proxy: nil}}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("health check: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("health check: %s answered %s", u, resp.Status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "serve's listen address host:port (default $"+config.EnvListen+" or "+config.DefaultListen+")")
	return cmd
}

// healthURL is the /healthz URL of a serve listening on addr. A wildcard
// host (empty, 0.0.0.0, ::) becomes 127.0.0.1.
func healthURL(addr string) (string, error) {
	if err := config.CheckListen(addr); err != nil {
		return "", err
	}
	host, port, _ := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}
