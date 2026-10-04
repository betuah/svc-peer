package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/betuah/svc-peer/internal/agent"
)

func main() {
	configPath := flag.String("config", "configs/agent.example.yaml", "path to agent config YAML")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	a, err := agent.New(cfg, log)
	if err != nil {
		log.Error("init agent", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := a.Run(ctx); err != nil && err != context.Canceled {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}
