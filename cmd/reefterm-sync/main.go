// Command reefterm-sync runs the self-hosted sync server. Configuration is
// entirely environment variables (see internal/config), the usual shape for
// something meant to run in a container.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reefterm/sync-server/internal/api"
	"github.com/reefterm/sync-server/internal/config"
	"github.com/reefterm/sync-server/internal/store/sqlite"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := config.Load()

	st, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		log.Error("open database", "path", cfg.DBPath, "error", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	srv := api.New(st, cfg, log)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "db", cfg.DBPath, "registration_open", cfg.AllowRegistration)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "error", err)
	}
}
