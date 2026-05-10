package main

import (
	"fmt"
	"os"

	"github.com/youwantitdarker28/Command-Guard/internal/analyzer"
	cgexec "github.com/youwantitdarker28/Command-Guard/internal/exec"
	"github.com/youwantitdarker28/Command-Guard/internal/policy"
	"github.com/youwantitdarker28/Command-Guard/internal/ui"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: digest <command> [args...]")
		os.Exit(1)
	}

	analysis := analyzer.Analyze(args)
	cfg, err := policy.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load policy: %v\n", err)
	}

	eval := policy.Evaluate(cfg, analysis)
	switch eval.Action {
	case policy.ActionAllow:
		audit(cfg, analysis, eval, "auto_allowed")
		runAndExit(args)
	case policy.ActionBlock:
		fmt.Fprintf(os.Stderr, "blocked by policy: command %q is not allowed\n", analysis.Command)
		audit(cfg, analysis, eval, "blocked")
		os.Exit(1)
	default:
		approved, err := ui.Run(analysis)
		if err != nil {
			fmt.Fprintf(os.Stderr, "digest ui error: %v\n", err)
			audit(cfg, analysis, eval, "aborted")
			os.Exit(1)
		}
		if !approved {
			audit(cfg, analysis, eval, "aborted")
			os.Exit(1)
		}
		audit(cfg, analysis, eval, "approved")
		runAndExit(args)
	}
}

func runAndExit(args []string) {
	exitCode, err := cgexec.Run(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest exec error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

func audit(cfg *policy.Config, analysis analyzer.Result, eval policy.Evaluation, decision string) {
	err := policy.AppendAudit(cfg, policy.Record{
		Command:      analysis.Command,
		Risk:         analysis.Risk.String(),
		Category:     eval.Category,
		PolicyAction: eval.Action,
		Decision:     decision,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write audit log: %v\n", err)
	}
}
