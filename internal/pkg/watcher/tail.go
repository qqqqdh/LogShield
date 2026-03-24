// internal/pkg/watcher/tail.go
package watcher

import (
	"io"
	"os"
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
	offset, _ := file.Seek(0, io.SeekEnd)

	for {
		select {
		case <-stop:
			return nil
		default:
			// 새로운 데이터 읽기 시도
			buf := make([]byte, 1024)
			n, err := file.Read(buf)
			if n > 0 {
				out <- string(buf[:n])
				offset += int64(n)
				file.Seek(offset, io.SeekStart)
			} else if err == io.EOF {
				// 새로운 내용이 없으면 잠시 대기 (폴링 방식)
				time.Sleep(500 * time.Millisecond)
			} else {
				return err
			}
		}
	}
}
