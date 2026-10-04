package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/betuah/svc-peer/internal/hub"
)

func main() {
	configPath := flag.String("config", "configs/hub.example.yaml", "path to hub config YAML")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := hub.LoadConfig(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	h, err := hub.New(cfg, log)
	if err != nil {
		log.Error("init hub", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := h.ListenAndServe(ctx); err != nil {
		log.Error("hub stopped", "err", err)
		os.Exit(1)
	}
}
