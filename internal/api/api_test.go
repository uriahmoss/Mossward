package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"mossward/internal/config"
	"mossward/internal/scanner"
	"mossward/internal/store"
)

func testHandler(t *testing.T) (http.Handler, *store.FileStore) {
	t.Helper()
	cfg := config.Config{
		AllowedCIDRs:   []string{"127.0.0.0/8", "::1/128"},
		AllowedPorts:   map[int]bool{80: true, 443: true},
		MaxTargets:     10,
		MaxConcurrent:  2,
		QueueSize:      2,
		ConnectTimeout: 20 * time.Millisecond,
	}
	repository, err := store.NewFileStore(filepath.Join(t.TempDir(), "scans.json"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scanner.New(cfg, repository)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Shutdown)
	return New(cfg, repository, engine), repository
}

func TestCreateScanAcceptsAuthorizedTarget(t *testing.T) {
	handler, repository := testHandler(t)
	body := bytes.NewBufferString(`{"name":"test","targets":["127.0.0.1"],"ports":[80]}`)
	request := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected %d, got %d: %s", http.StatusAccepted, response.Code, response.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		scan, err := repository.Get(created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if scan.Status == "completed" || scan.Status == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan did not reach a terminal state")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCreateScanRejectsPublicTarget(t *testing.T) {
	handler, _ := testHandler(t)
	body := bytes.NewBufferString(`{"name":"test","targets":["8.8.8.8"],"ports":[443]}`)
	request := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, response.Code)
	}
	var result map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["error"] == "" {
		t.Fatal("expected policy error")
	}
}

func TestCreateScanRejectsTrailingJSON(t *testing.T) {
	handler, _ := testHandler(t)
	body := bytes.NewBufferString(`{"targets":["127.0.0.1"]} {"unexpected":true}`)
	request := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, response.Code)
	}
}

func TestWebRoutesServeHomeAndScanner(t *testing.T) {
	handler, _ := testHandler(t)
	for _, path := range []string{"/", "/scan.html", "/styles.css", "/scan.js"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("%s: expected %d, got %d", path, http.StatusOK, response.Code)
		}
	}
}
