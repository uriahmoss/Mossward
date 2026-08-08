package workerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mossward/internal/model"
)

const (
	workerTransportResponseLimit = 1 << 20
	workerPollPath               = "/api/scanner-worker/v1/jobs/poll"
	workerRenewPath              = "/api/scanner-worker/v1/jobs/lease/renew"
	workerEvidencePath           = "/api/scanner-worker/v1/jobs/evidence"
	workerCompletionPath         = "/api/scanner-worker/v1/jobs/result"
)

var ErrNoWorkerJob = errors.New("no scanner-worker job is available")

type Transport struct {
	baseURL *url.URL
	client  *http.Client
}

type TransportError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("scanner-worker server returned HTTP %d", e.StatusCode)
}

func NewTransport(rawBaseURL string, client *http.Client) (*Transport, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil || baseURL.Scheme != "https" || baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("scanner-worker server URL must be an HTTPS origin")
	}
	if baseURL.Path != "" && baseURL.Path != "/" {
		return nil, errors.New("scanner-worker server URL must not contain a path")
	}
	if client == nil {
		return nil, errors.New("scanner-worker mTLS HTTP client is unavailable")
	}
	baseURL.Path = ""
	return &Transport{baseURL: baseURL, client: client}, nil
}

func (t *Transport) Poll(ctx context.Context) (model.WorkerJobLease, error) {
	var lease model.WorkerJobLease
	response, err := t.request(ctx, workerPollPath, nil)
	if err != nil {
		return lease, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return lease, ErrNoWorkerJob
	}
	if response.StatusCode != http.StatusOK {
		return lease, transportResponseError(response)
	}
	if err := decodeTransportJSON(response.Body, &lease); err != nil {
		return lease, fmt.Errorf("decode scanner-worker job lease: %w", err)
	}
	return lease, nil
}

func (t *Transport) Renew(ctx context.Context, renewal model.WorkerJobLeaseRenewal) (model.WorkerJobLeaseRenewal, error) {
	var result model.WorkerJobLeaseRenewal
	payload, err := json.Marshal(renewal)
	if err != nil {
		return result, err
	}
	response, err := t.request(ctx, workerRenewPath, payload)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, transportResponseError(response)
	}
	if err := decodeTransportJSON(response.Body, &result); err != nil {
		return result, fmt.Errorf("decode scanner-worker lease renewal: %w", err)
	}
	return result, nil
}

func (t *Transport) Deliver(ctx context.Context, message OutboxMessage) error {
	path := workerEvidencePath
	if message.Kind == OutboxCompletion {
		path = workerCompletionPath
	} else if message.Kind != OutboxEvidence {
		return errors.New("scanner-worker outbox message kind is unsupported")
	}
	response, err := t.request(ctx, path, message.Payload)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, workerTransportResponseLimit))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return transportResponseError(response)
	}
	return nil
}

func (t *Transport) ForwardOutbox(ctx context.Context, outbox *Outbox, maximum int) (int, error) {
	if outbox == nil {
		return 0, errors.New("scanner-worker outbox is unavailable")
	}
	return outbox.ForwardPending(ctx, maximum, t.Deliver)
}

func (t *Transport) request(ctx context.Context, path string, payload []byte) (*http.Response, error) {
	requestURL := *t.baseURL
	requestURL.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := t.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("contact scanner-worker server: %w", err)
	}
	return response, nil
}

func decodeTransportJSON(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, workerTransportResponseLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("scanner-worker response contains trailing data")
	}
	return nil
}

func transportResponseError(response *http.Response) error {
	retryAfter := time.Duration(0)
	if seconds, err := time.ParseDuration(strings.TrimSpace(response.Header.Get("Retry-After")) + "s"); err == nil {
		retryAfter = seconds
	}
	return &TransportError{StatusCode: response.StatusCode, RetryAfter: retryAfter}
}
