// Command relgate is a release gate for services you own: it runs passive security
// checks and a bounded load test against a target listed in its config, then prints
// a report and exits non-zero if the gate fails, so it can guard a CI pipeline.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arseniyyx/relgate/internal/config"
	"github.com/arseniyyx/relgate/internal/run"
)

func main() {
	configPath := flag.String("config", "relgate.yaml", "path to the config file")
	mdPath := flag.String("md", "", "also write a Markdown report to this file (for PR comments)")
	flag.Parse()

	if err := realMain(*configPath, *mdPath); err != nil {
		fmt.Fprintln(os.Stderr, "relgate:", err)
		os.Exit(2) // 2 = could not run; 1 = ran but gate failed
	}
}

func realMain(configPath, mdPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := run.NewClient(cfg)
	rep := run.Execute(ctx, client, cfg)

	fmt.Print(rep.Console())

	if mdPath != "" {
		if err := os.WriteFile(mdPath, []byte(rep.Markdown()), 0o644); err != nil {
			return fmt.Errorf("write markdown report: %w", err)
		}
	}

	if !rep.Passed {
		os.Exit(1)
	}
	return nil
}
