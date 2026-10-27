package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go-logshield/internal/benchmark"
	"go-logshield/internal/normalizer"
)

type datasetFile struct {
	ReferenceTime string             `json:"reference_time"`
	Samples       []benchmark.Sample `json:"samples"`
}

func loadDataset(path string) ([]benchmark.Sample, time.Time, error) {
	var file datasetFile
	if path == "" {
		file.ReferenceTime = "2026-10-28T12:00:00Z"
		file.Samples = prepareDataset()
		fillSyntheticEvents(file.Samples)
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, time.Time{}, err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&file); err != nil {
			return nil, time.Time{}, err
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, time.Time{}, errors.New("dataset has trailing content")
		}
	}
	reference, err := time.Parse(time.RFC3339, file.ReferenceTime)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("reference_time: %w", err)
	}
	if len(file.Samples) == 0 {
		return nil, time.Time{}, errors.New("dataset has no samples")
	}
	seen := make(map[string]bool)
	for i := range file.Samples {
		sample := &file.Samples[i]
		if sample.ID == "" || seen[sample.ID] {
			return nil, time.Time{}, fmt.Errorf("missing or duplicate sample id %q", sample.ID)
		}
		seen[sample.ID] = true
		if sample.IsAttackGround && (sample.GroundTechnique == "" || sample.GroundTechnique == "None") {
			return nil, time.Time{}, fmt.Errorf("sample %s missing attack technique", sample.ID)
		}
		if len(sample.Events) == 0 {
			return nil, time.Time{}, fmt.Errorf("sample %s has no events", sample.ID)
		}
		lines := make([]string, 0, len(sample.Events))
		for j, line := range sample.Events {
			ev, err := normalizer.ParseLineAt(line, reference)
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("sample %s event %d: %w", sample.ID, j+1, err)
			}
			lines = append(lines, fmt.Sprintf("(%d) At %s, IP %s performed service=%s action=%s status=%s user=%s path=%s", j+1, ev.TS.Format(time.RFC3339), ev.IP, ev.Service, ev.Action, ev.Status, ev.User, ev.Path))
		}
		sample.BehaviorContext = strings.Join(lines, "\n")
	}
	return file.Samples, reference, nil
}

func fillSyntheticEvents(samples []benchmark.Sample) {
	if len(samples) != 7 {
		return
	}
	samples[0].Events = syntheticLines("web", "get", "200", "10.0.0.1", []string{"/index.html", "/style.css", "/favicon.ico"}, 3)
	samples[1].Events = append(syntheticLines("auth", "login", "SUCCESS", "192.0.2.15", nil, 1), syntheticLines("web", "get", "200", "192.0.2.15", []string{"/dashboard"}, 1)...)
	samples[2].Events = syntheticLines("ssh", "auth", "SUCCESS", "10.0.0.50", nil, 1)
	samples[3].Events = syntheticLines("auth", "login", "FAIL", "203.0.113.10", nil, 5)
	samples[4].Events = syntheticLines("ssh", "auth", "FAIL", "198.51.100.23", nil, 6)
	samples[5].Events = syntheticLines("web", "get", "404", "198.51.100.45", []string{"/.env", "/admin", "/config", "/backup"}, 4)
	samples[6].Events = syntheticLines("web", "get", "404", "172.16.0.99", []string{"/wp-login.php", "/phpmyadmin", "/.git/config", "/admin"}, 4)
	for i := range samples {
		samples[i].BehaviorContext = ""
	}
}

func syntheticLines(service, action, status, ip string, paths []string, count int) []string {
	result := make([]string, 0, count)
	base := time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	for i := 0; i < count; i++ {
		path := ""
		if len(paths) > 0 {
			path = paths[i%len(paths)]
		}
		result = append(result, fmt.Sprintf("%s service=%s action=%s user=test ip=%s status=%s path=%s", base.Add(time.Duration(i)*time.Second).Format(time.RFC3339), service, action, ip, status, path))
	}
	return result
}
