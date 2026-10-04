package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/betuah/svc-peer/internal/relay"
)

func main() {
	configPath := flag.String("config", "configs/relay.example.yaml", "path to relay config YAML")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := relay.LoadConfig(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	srv, err := relay.New(cfg, log)
	if err != nil {
		log.Error("init relay", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Error("relay stopped", "err", err)
		os.Exit(1)
	}
}
