// internal/pkg/watcher/tail.go
package watcher

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// TailFile: 파일에 추가되는 내용을 실시간으로 읽어 채널로 보냅니다.
func TailFile(path string, out chan<- string, stop <-chan struct{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	// 파일의 맨 끝으로 이동
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	var pending string

	for {
		select {
		case <-stop:
			return nil
		default:
			// 줄이 완성될 때까지 보관하여 partial line을 전달하지 않는다.
			chunk, err := reader.ReadString('\n')
			pending += chunk
			if len(pending) > 1024*1024 {
				return fmt.Errorf("log line exceeds 1 MiB: %s", path)
			}
			if strings.HasSuffix(pending, "\n") {
				line := strings.TrimSuffix(pending, "\n")
				line = strings.TrimSuffix(line, "\r")
				pending = ""
				select {
				case out <- line:
				case <-stop:
					return nil
				}
			}
			if err == nil {
				continue
			}
			if !errors.Is(err, io.EOF) {
				return err
			}

			// Reopen rotated files and reset the read position after truncation.
			pathInfo, statErr := os.Stat(path)
			if statErr == nil {
				currentInfo, err := file.Stat()
				if err != nil {
					return err
				}
				if !os.SameFile(pathInfo, currentInfo) {
					next, err := os.Open(path)
					if err == nil {
						_ = file.Close()
						file = next
						reader.Reset(file)
						pending = ""
						continue
					}
				} else {
					offset, err := file.Seek(0, io.SeekCurrent)
					if err != nil {
						return err
					}
					if pathInfo.Size() < offset {
						if _, err := file.Seek(0, io.SeekStart); err != nil {
							return err
						}
						reader.Reset(file)
						pending = ""
						continue
					}
				}
			}

			// 새로운 내용이 없으면 잠시 대기 (폴링 방식)
			timer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-timer.C:
			case <-stop:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return nil
			}
		}
	}
}
