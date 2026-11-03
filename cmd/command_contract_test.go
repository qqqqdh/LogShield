package cmd_test

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-logshield/internal/normalizer"
)

func buildCommand(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".exe")
	cmd := exec.Command("go", "build", "-o", path, "./cmd/"+name)
	cmd.Dir = ".."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return path
}

func invoke(t *testing.T, binary string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = t.TempDir()
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return string(output), err
}

func TestCommandRolesAndHelp(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
	}{
		{"loggen", []string{"-out string", "-count int", "-force", "./sample-logs"}},
		{"logshield-tui", []string{"-log-dir string", "-alerts-file string"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := invoke(t, buildCommand(t, tc.name), "-h")
			if err != nil {
				t.Fatalf("help must return without starting UI: %v\n%.500s", err, output)
			}
			for _, flag := range tc.flags {
				if !strings.Contains(output, flag) {
					t.Errorf("%s help missing %s\n%s", tc.name, flag, output)
				}
			}
		})
	}
}

func TestGeneratorDoesNotOverwriteExistingLogs(t *testing.T) {
	binary := buildCommand(t, "loggen")
	for _, name := range []string{"auth.log", "ssh.log", "web.log"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			marker := []byte("existing production-like marker\n")
			if err := os.WriteFile(filepath.Join(dir, name), marker, 0600); err != nil {
				t.Fatal(err)
			}
			if output, err := invoke(t, binary, "-out", dir, "-count", "3"); err == nil {
				t.Errorf("existing log must be refused: %s", output)
			}
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || string(got) != string(marker) {
				t.Fatalf("existing log changed: %q err=%v", got, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("preflight produced partial files: count=%d err=%v", len(entries), err)
			}
		})
	}
}

func TestGeneratorProducesParseableLogsAndProtectsOtherFiles(t *testing.T) {
	binary := buildCommand(t, "loggen")
	dir := t.TempDir()
	markerPath := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(markerPath, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := invoke(t, binary, "-out", dir, "-count", "3")
	if err != nil {
		t.Fatalf("generator failed: %v\n%s", err, output)
	}
	for _, name := range []string{"auth.log", "ssh.log", "web.log"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		count := 0
		for scanner.Scan() {
			count++
			if _, err := normalizer.ParseLine(scanner.Text()); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		if count != 3 {
			t.Errorf("%s lines=%d, want3", name, count)
		}
	}
	if output, err := invoke(t, binary, "-out", dir, "-count", "1", "-force"); err != nil {
		t.Fatalf("explicit replacement failed: %v %s", err, output)
	}
	data, err := os.ReadFile(markerPath)
	if err != nil || string(data) != "keep" {
		t.Fatalf("unrelated file changed: %q %v", data, err)
	}
}

func TestGeneratorRejectsInvalidCountBeforeCreatingDirectory(t *testing.T) {
	binary := buildCommand(t, "loggen")
	for _, count := range []string{"0", "-1"} {
		dir := filepath.Join(t.TempDir(), "new-output")
		output, err := invoke(t, binary, "-out", dir, "-count", count)
		if err == nil {
			t.Fatalf("invalid count accepted: %s", output)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("invalid input touched output: %v", err)
		}
	}
}

func TestGeneratorRejectsMonitorFlagsWithoutWriting(t *testing.T) {
	binary := buildCommand(t, "loggen")
	dir := filepath.Join(t.TempDir(), "output")
	output, err := invoke(t, binary, "-out", dir, "-log-dir", dir)
	if err == nil || !strings.Contains(output, "flag provided but not defined") {
		t.Fatalf("monitor flag accepted: %v %s", err, output)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("usage error wrote output: %v", err)
	}
}
