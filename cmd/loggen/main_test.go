package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestGeneratorsReturnWriteErrors(t *testing.T) {
	for _, generate := range []func(io.Writer, time.Time, int) error{generateAuthLog, generateSSHLog, generateWebLog} {
		if err := generate(failingWriter{}, time.Now(), 1); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("write failure hidden: %v", err)
		}
	}
}

func TestForceRejectsNonregularTargetBeforeChangingOtherLogs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "ssh.log"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := generateLogs(dir, 3, true); err == nil {
		t.Fatal("directory target accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("regular target changed before validation: %q %v", data, err)
	}
}

func TestGeneratorRejectsEmptyOutput(t *testing.T) {
	if err := generateLogs("", 3, false); err == nil {
		t.Fatal("empty output accepted")
	}
}
