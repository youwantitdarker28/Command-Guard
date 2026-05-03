package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/youwantitdarker28/Command-Guard/internal/analyzer"
	execpkg "github.com/youwantitdarker28/Command-Guard/internal/exec"
	"github.com/youwantitdarker28/Command-Guard/internal/ui"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: digest <command> [args...]")
		os.Exit(1)
	}

	result := analyzer.Analyze(args)
	approved, err := ui.Run(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest: failed to render confirmation UI: %v\n", err)
		os.Exit(1)
	}
	if !approved {
		fmt.Fprintf(os.Stderr, "digest: aborted by user — command not executed: %s\n", strings.Join(args, " "))
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "digest: executing: %s\n", strings.Join(args, " "))
	exitCode, err := execpkg.Run(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}
