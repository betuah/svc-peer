package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/betuah/svc-peer/internal/hub"
	"github.com/betuah/svc-peer/internal/logging"
)

func main() {
	configPath := flag.String("config", "configs/hub.example.yaml", "path to hub config YAML")
	flag.Parse()

	cfg, err := hub.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	log, err := logging.New(logging.Config{Level: cfg.LogLevel, Format: cfg.LogFormat}, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
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
