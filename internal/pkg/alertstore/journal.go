package alertstore

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"go-logshield/internal/detector"
)

// Entry keeps event time in Alert.TS and the time LogShield recorded it.
type Entry struct {
	RecordedAt time.Time       `json:"recorded_at"`
	Alert      detector.Result `json:"alert"`
}

type Journal struct {
	mu   sync.Mutex
	file *os.File
}

func Open(path string) (*Journal, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &Journal{file: file}, nil
}

func (j *Journal) Append(alert detector.Result) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return errors.New("alert journal is closed")
	}
	data, err := json.Marshal(Entry{RecordedAt: time.Now().UTC(), Alert: alert})
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := j.file.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return j.file.Sync()
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	syncErr := j.file.Sync()
	closeErr := j.file.Close()
	j.file = nil
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
