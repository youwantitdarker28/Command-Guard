// Package exec provides a thin wrapper around os/exec that runs a command
// with its stdin, stdout, and stderr connected directly to the parent process,
// preserving full interactivity and streaming output in real time.
//
// Run returns the child process exit code as the first return value so that
// callers can propagate it faithfully without calling os.Exit inside a library.
package exec

import (
	"fmt"
	"os"
	osexec "os/exec"
)

// Run executes args[0] with args[1:] as its arguments, wiring stdin, stdout,
// and stderr directly to the parent process.
//
// On success it returns (0, nil).
// If the child exits with a non-zero status, it returns (exitCode, nil) so
// the caller can propagate it without treating it as an unexpected error.
// Any other failure (command not found, permission denied, etc.) returns (1, err).
func Run(args []string) (int, error) {
	if len(args) == 0 {
		return 1, fmt.Errorf("exec: no command provided")
	}

	cmd := osexec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*osexec.ExitError); ok {
			// Child exited non-zero — not a tooling error, just a status code.
			return exitErr.ExitCode(), nil
		}
		return 1, fmt.Errorf("exec: %w", err)
	}
	return 0, nil
}
