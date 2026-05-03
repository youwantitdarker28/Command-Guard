// Package exec provides a thin wrapper around os/exec that runs a command
// with its stdin, stdout, and stderr connected directly to the parent process,
// preserving full interactivity and streaming output in real time.
package exec

import (
	"fmt"
	"os"
	osexec "os/exec"
)

// Run executes args[0] with args[1:] as its arguments.
// stdin, stdout, and stderr are all forwarded to the parent process so that
// interactive programs (vim, python REPL, etc.) work correctly.
// The process exit code is propagated: if the child exits non-zero, Run
// calls os.Exit with that code rather than returning an error, so the caller
// does not need to handle exit-code unwrapping.
func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("exec: no command provided")
	}

	cmd := osexec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*osexec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("exec: %w", err)
	}
	return nil
}
