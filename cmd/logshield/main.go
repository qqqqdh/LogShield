package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"go-logshield/internal/analyzer"
	"go-logshield/internal/normalizer"
)

func main() {
	logDir := flag.String("log-dir", "./logs", "분석할 로그 파일이 위치한 디렉터리")
	flag.Parse()

	// 1) 로그 파일 찾기
	pattern := filepath.Join(*logDir, "*.log")
	files, err := filepath.Glob(pattern)
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatalf("no log files found in %s", *logDir)
	}

	// 2) 공통 분석 파이프라인 초기화
	engine := analyzer.NewDefault()

	// 3) 로그 파일 순회
	for _, file := range files {
		fmt.Println("===", file, "===")
		if err := processFile(file, engine); err != nil {
			log.Fatal(err)
		}
	}
}

func processFile(path string, engine *analyzer.Analyzer) error {
	fp, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	// A user-agent or request line can exceed Scanner's default 64 KiB limit.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		ev, results, err := engine.ProcessLine(line)
		if errors.Is(err, normalizer.ErrNonEvent) {
			continue
		}
		if err != nil {
			fmt.Println("PARSE_ERR:", err, "line:", line)
			continue
		}

		fmt.Printf(
			"%s service=%s action=%s user=%s ip=%s status=%s path=%s\n",
			ev.TS.Format("15:04:05"),
			ev.Service,
			ev.Action,
			ev.User,
			ev.IP,
			ev.Status,
			ev.Path,
		)
		for _, result := range results {
			fmt.Println(result.Message)
		}
	}
	return scanner.Err()
}
