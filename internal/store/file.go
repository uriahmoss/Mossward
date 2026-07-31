package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"mossward/internal/model"
)

var ErrNotFound = errors.New("scan not found")

type FileStore struct {
	mu    sync.RWMutex
	path  string
	scans map[string]model.Scan
}

func (s *FileStore) ReconcileInterrupted() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	now := time.Now().UTC()
	for id, scan := range s.scans {
		if scan.Status != model.StatusQueued && scan.Status != model.StatusRunning {
			continue
		}
		scan.Status = model.StatusFailed
		scan.Error = "scan interrupted by a previous process shutdown"
		scan.CompletedAt = &now
		s.scans[id] = scan
		changed = true
	}
	if !changed {
		return nil
	}
	return s.flush()
}

func NewFileStore(path string) (*FileStore, error) {
	s := &FileStore{path: path, scans: make(map[string]model.Scan)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &s.scans); err != nil {
			return nil, err
		}
		for id, scan := range s.scans {
			s.scans[id] = migrateLegacyObservations(scan)
		}
	}
	return s, nil
}

func (s *FileStore) Save(scan model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans[scan.ID] = cloneScan(scan)
	return s.flush()
}

func (s *FileStore) Get(id string) (model.Scan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scan, ok := s.scans[id]
	if !ok {
		return model.Scan{}, ErrNotFound
	}
	return cloneScan(scan), nil
}

func (s *FileStore) List() []model.Scan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scans := make([]model.Scan, 0, len(s.scans))
	for _, scan := range s.scans {
		scans = append(scans, cloneScan(scan))
	}
	sort.Slice(scans, func(i, j int) bool { return scans[i].CreatedAt.After(scans[j].CreatedAt) })
	return scans
}

func cloneScan(scan model.Scan) model.Scan {
	scan.Targets = append([]model.Target(nil), scan.Targets...)
	scan.Ports = append([]int(nil), scan.Ports...)
	scan.Findings = append([]model.Finding(nil), scan.Findings...)
	scan.Observations = append([]model.ServiceObservation(nil), scan.Observations...)
	for index := range scan.Observations {
		if scan.Observations[index].Metadata != nil {
			metadata := make(map[string]string, len(scan.Observations[index].Metadata))
			for key, value := range scan.Observations[index].Metadata {
				metadata[key] = value
			}
			scan.Observations[index].Metadata = metadata
		}
	}
	if scan.StartedAt != nil {
		started := *scan.StartedAt
		scan.StartedAt = &started
	}
	if scan.CompletedAt != nil {
		completed := *scan.CompletedAt
		scan.CompletedAt = &completed
	}
	return scan
}

func migrateLegacyObservations(scan model.Scan) model.Scan {
	if scan.Observations == nil {
		scan.Observations = []model.ServiceObservation{}
	}
	if scan.Findings == nil {
		scan.Findings = []model.Finding{}
	}
	currentFindings := scan.Findings[:0]
	for _, finding := range scan.Findings {
		if finding.CheckID == "" && finding.Severity == "info" {
			scan.Observations = append(scan.Observations, model.ServiceObservation{
				ID: finding.ID, Target: finding.Target, Address: finding.Address,
				Port: finding.Port, Protocol: finding.Service, Confidence: "low",
				Evidence: finding.Evidence, ObservedAt: finding.ObservedAt,
			})
			continue
		}
		currentFindings = append(currentFindings, finding)
	}
	scan.Findings = currentFindings
	return scan
}

func (s *FileStore) flush() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.scans, "", "  ")
	if err != nil {
		return err
	}
	temp := s.path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, s.path)
}
