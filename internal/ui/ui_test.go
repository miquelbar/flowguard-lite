package ui

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// TestJavaScriptSyntax verifies that app.js contains valid JavaScript syntax
// by invoking "node --check" if the node executable is present on the host.
func TestJavaScriptSyntax(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node executable not found on host machine, skipping JS syntax check")
		return
	}

	jsFile := filepath.Join("assets", "app.js")
	cmd := exec.Command(nodePath, "--check", jsFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("JavaScript syntax check failed for %s:\n%s", jsFile, string(output))
	}
}
