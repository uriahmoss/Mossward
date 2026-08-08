//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "mossward-agent-updater is available only on Windows")
	os.Exit(1)
}
