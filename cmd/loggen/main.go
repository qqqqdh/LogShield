package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// LogGenerator simulates network and authentication logs for LogShield testing.
func main() {
	outDir := flag.String("out", "./sample-logs", "Output directory for synthetic test logs")
	count := flag.Int("count", 100, "Number of log entries per file (positive)")
	force := flag.Bool("force", false, "Replace existing regular test log files in the output directory")
	flag.Parse()
	if err := generateLogs(*outDir, *count, *force); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated %d entries per file in %s (auth.log, ssh.log, web.log)\n", *count, *outDir)
}

func generateLogs(outDir string, count int, force bool) error {
	if count <= 0 {
		return errors.New("count must be positive")
	}
	if outDir == "" {
		return errors.New("out directory must not be empty")
	}
	targets := []struct {
		name  string
		write func(io.Writer, time.Time, int) error
	}{
		{"auth.log", generateAuthLog}, {"ssh.log", generateSSHLog}, {"web.log", generateWebLog},
	}
	// Check every target before creating or replacing any output.
	for _, target := range targets {
		path := filepath.Join(outDir, target.name)
		info, err := os.Lstat(path)
		if err == nil {
			if !force {
				return fmt.Errorf("%w: %s (use -force to replace test logs)", os.ErrExist, path)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("refusing non-regular target %s", path)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	// shortcut: forced replacement is per file; stage outputs if all-file atomicity becomes required.
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	start := time.Now()
	for _, target := range targets {
		path := filepath.Join(outDir, target.name)
		file, err := os.OpenFile(path, flags, 0600)
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		writeErr := target.write(file, start, count)
		closeErr := file.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return fmt.Errorf("generate %s: %w", path, err)
		}
	}
	return nil
}

func generateAuthLog(writer io.Writer, startTime time.Time, count int) error {

	users := []string{"alice", "bob", "charlie", "root", "admin"}
	ips := []string{"10.0.0.5", "10.0.0.12", "192.168.1.100", "203.0.113.10"}

	currTime := startTime.Add(-time.Duration(count) * time.Second)

	for i := 0; i < count; i++ {
		currTime = currTime.Add(time.Second)
		ip := ips[rand.Intn(len(ips))]
		user := users[rand.Intn(len(users))]

		// Introduce Brute Force attack pattern (IP 203.0.113.10 rapidly failing)
		status := "success"
		if ip == "203.0.113.10" || rand.Float32() < 0.3 {
			status = "FAIL"
		}

		line := fmt.Sprintf("%s service=auth action=login user=\"%s\" ip=\"%s\" status=\"%s\"\n",
			currTime.Format(time.RFC3339), user, ip, status)
		if _, err := io.WriteString(writer, line); err != nil {
			return err
		}
	}
	return nil
}

func generateSSHLog(writer io.Writer, startTime time.Time, count int) error {

	ips := []string{"198.51.100.23", "10.0.0.50", "172.16.0.4"}
	currTime := startTime.Add(-time.Duration(count) * time.Second)

	for i := 0; i < count; i++ {
		currTime = currTime.Add(time.Second)
		ip := ips[rand.Intn(len(ips))]

		status := "success"
		user := "ubuntu"
		if ip == "198.51.100.23" {
			status = "failed"
			user = "root"
		}

		line := fmt.Sprintf("%s service=ssh action=login user=\"%s\" ip=\"%s\" status=\"%s\"\n",
			currTime.Format(time.RFC3339), user, ip, status)
		if _, err := io.WriteString(writer, line); err != nil {
			return err
		}
	}
	return nil
}

func generateWebLog(writer io.Writer, startTime time.Time, count int) error {

	normalPaths := []string{"/index.html", "/about", "/login", "/dashboard", "/api/v1/user"}
	attackPaths := []string{"/.env", "/admin", "/wp-login.php", "/config.json", "/backup.sql"}
	ips := []string{"192.168.1.15", "10.0.0.99", "198.51.100.45"}

	currTime := startTime.Add(-time.Duration(count) * time.Second)

	for i := 0; i < count; i++ {
		currTime = currTime.Add(time.Second)
		ip := ips[rand.Intn(len(ips))]

		path := normalPaths[rand.Intn(len(normalPaths))]
		status := "200"

		// Introduce Web Scanning / Enumeration pattern (IP 198.51.100.45)
		if ip == "198.51.100.45" {
			path = attackPaths[rand.Intn(len(attackPaths))]
			status = "404"
		}

		line := fmt.Sprintf("%s service=web action=get user=\"guest\" ip=\"%s\" status=\"%s\" path=\"%s\"\n",
			currTime.Format(time.RFC3339), ip, status, path)
		if _, err := io.WriteString(writer, line); err != nil {
			return err
		}
	}
	return nil
}
