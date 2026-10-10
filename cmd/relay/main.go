package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/betuah/svc-peer/internal/logging"
	"github.com/betuah/svc-peer/internal/relay"
)

func main() {
	configPath := flag.String("config", "configs/relay.example.yaml", "path to relay config YAML")
	flag.Parse()

	cfg, err := relay.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	log, err := logging.New(logging.Config{Level: cfg.LogLevel, Format: cfg.LogFormat}, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
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
