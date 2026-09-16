// internal/pkg/watcher/tail.go
package watcher

import (
	"bufio"
	"errors"
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
	defer file.Close()

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
