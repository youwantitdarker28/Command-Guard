package ui

import "os"

// stderr returns the stderr file; extracted here so it can be overridden in
// tests without touching the main Run function.
func stderr() *os.File { return os.Stderr }
