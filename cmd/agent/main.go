package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/betuah/svc-peer/internal/agent"
	"github.com/betuah/svc-peer/internal/logging"
)

func main() {
	configPath := flag.String("config", "configs/agent.example.yaml", "path to agent config YAML")
	flag.Parse()

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	log, err := logging.New(logging.Config{Level: cfg.LogLevel, Format: cfg.LogFormat}, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
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
