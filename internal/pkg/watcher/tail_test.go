package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTailFileFollowsRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.log")
	if err := os.WriteFile(path, []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := make(chan string, 10)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- TailFile(path, out, stop) }()
	defer func() {
		close(stop)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("tailer did not stop")
		}
	}()
	time.Sleep(200 * time.Millisecond)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("first\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	select {
	case line := <-out:
		if line != "first" {
			t.Fatalf("first line=%q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first line not tailed")
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Skipf("rotation cannot be simulated on this filesystem: %v", err)
	}
	if err := os.WriteFile(path, []byte("rotated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-out:
		if line != "rotated" {
			t.Fatalf("rotated line=%q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new file was not followed")
	}
}

func TestTailFileReadsAfterTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 100)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := make(chan string, 10)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- TailFile(path, out, stop) }()
	defer func() {
		close(stop)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("tailer did not stop")
		}
	}()
	time.Sleep(200 * time.Millisecond)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("first\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	select {
	case line := <-out:
		if line != "first" {
			t.Fatalf("first line=%q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first line not tailed")
	}
	if err := os.WriteFile(path, []byte("new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-out:
		if line != "new" {
			t.Fatalf("line after truncation=%q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("truncated file was not followed")
	}
}
