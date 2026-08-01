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

func testHandler(t *testing.T) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	cfg := config.Config{
		AllowedCIDRs:   []string{"127.0.0.0/8", "::1/128"},
		AllowedPorts:   map[int]bool{80: true, 443: true},
		MaxTargets:     10,
		MaxConcurrent:  2,
		QueueSize:      2,
		ConnectTimeout: 20 * time.Millisecond,
	}
	repository, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "mossward.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
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
	completed, err := repository.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.TotalChecks != 1 || completed.DoneChecks != 1 {
		t.Fatalf("expected completed progress 1/1, got %d/%d", completed.DoneChecks, completed.TotalChecks)
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
	for _, path := range []string{"/", "/scan.html", "/scan-detail.html", "/styles.css", "/home.js", "/scan.js", "/scan-detail.js"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("%s: expected %d, got %d", path, http.StatusOK, response.Code)
		}
		if response.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: missing Referrer-Policy security header", path)
		}
	}
}

func TestIntelligenceEndpointsReturnEmptyLocalFeed(t *testing.T) {
	handler, _ := testHandler(t)
	for _, path := range []string{"/api/intelligence/news", "/api/intelligence/status"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d: %s", path, response.Code, response.Body.String())
		}
	}
}

func TestGetScanReturnsProgressFields(t *testing.T) {
	handler, repository := testHandler(t)
	body := bytes.NewBufferString(`{"name":"progress","targets":["127.0.0.1"],"ports":[80,443]}`)
	createRequest := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, createRequest)

	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		scan, err := repository.Get(created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if scan.Status == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan did not complete")
		}
		time.Sleep(5 * time.Millisecond)
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/api/scans/"+created.ID, nil)
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, getResponse.Code)
	}
	var result struct {
		Total int `json:"total_checks"`
		Done  int `json:"done_checks"`
	}
	if err := json.Unmarshal(getResponse.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 || result.Done != 2 {
		t.Fatalf("expected progress 2/2, got %d/%d", result.Done, result.Total)
	}
}
