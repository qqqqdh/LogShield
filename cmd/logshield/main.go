package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
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

	// 3) 파일 경계를 넘어 이벤트 시각순으로 분석
	records, err := normalizer.ReadBatch(files)
	if err != nil {
		log.Fatal(err)
	}
	for _, record := range records {
		ev, err := record.Event, record.Err
		if errors.Is(err, normalizer.ErrNonEvent) {
			continue
		}
		if err != nil {
			fmt.Println("PARSE_ERR:", err, "line:", record.Line)
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
		for _, result := range engine.Process(ev) {
			fmt.Println(result.Message)
		}
	}
}
