package workerclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mossward/internal/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func transportTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestTransportPollRenewAndOrderedOutboxDelivery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var mu sync.Mutex
	delivered := []string{}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case workerPollPath:
			body, _ := json.Marshal(model.WorkerJobLease{Envelope: model.SignedWorkerJob{Job: model.WorkerJob{ID: "job"}}, Token: "token", ExpiresAt: now.Add(time.Minute)})
			return transportTestResponse(http.StatusOK, string(body)), nil
		case workerRenewPath:
			var renewal model.WorkerJobLeaseRenewal
			_ = json.NewDecoder(r.Body).Decode(&renewal)
			renewal.ExpiresAt = now.Add(2 * time.Minute)
			body, _ := json.Marshal(renewal)
			return transportTestResponse(http.StatusOK, string(body)), nil
		case workerEvidencePath, workerCompletionPath:
			mu.Lock()
			delivered = append(delivered, r.URL.Path)
			mu.Unlock()
			return transportTestResponse(http.StatusAccepted, ""), nil
		default:
			return transportTestResponse(http.StatusNotFound, ""), nil
		}
	})}
	transport, err := NewTransport("https://worker.test", client)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := transport.Poll(context.Background())
	if err != nil || lease.Envelope.Job.ID != "job" {
		t.Fatalf("worker poll failed: %#v %v", lease, err)
	}
	renewal, err := transport.Renew(context.Background(), model.WorkerJobLeaseRenewal{JobID: "job", LeaseToken: lease.Token})
	if err != nil || !renewal.ExpiresAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("worker lease renewal failed: %#v %v", renewal, err)
	}
	state := filepath.Join(t.TempDir(), "state")
	outbox, err := OpenOutbox(filepath.Join(state, "outbox.db"), filepath.Join(state, "outbox.key"), OutboxLimits{MaxItems: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	for _, message := range []OutboxMessage{
		{ID: "z-first", Kind: OutboxEvidence, Payload: []byte(`{"batch":1}`), CreatedAt: now},
		{ID: "a-second", Kind: OutboxCompletion, Payload: []byte(`{"result":1}`), CreatedAt: now},
	} {
		if err := outbox.Enqueue(message); err != nil {
			t.Fatal(err)
		}
	}
	forwarded, err := transport.ForwardOutbox(context.Background(), outbox, 10)
	if err != nil || forwarded != 2 {
		t.Fatalf("worker outbox forwarding failed: forwarded=%d err=%v", forwarded, err)
	}
	if len(delivered) != 2 || delivered[0] != workerEvidencePath || delivered[1] != workerCompletionPath {
		t.Fatalf("worker outbox insertion order changed: %v", delivered)
	}
	if _, err := outbox.Peek(); err != ErrOutboxEmpty {
		t.Fatalf("acknowledged worker messages remained queued: %v", err)
	}
}

func TestTransportDoesNotAcknowledgeRejectedMessage(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return transportTestResponse(http.StatusServiceUnavailable, "retry"), nil
	})}
	transport, _ := NewTransport("https://worker.test", client)
	state := filepath.Join(t.TempDir(), "state")
	outbox, err := OpenOutbox(filepath.Join(state, "outbox.db"), filepath.Join(state, "outbox.key"), OutboxLimits{MaxItems: 2, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer outbox.Close()
	message := OutboxMessage{ID: "message", Kind: OutboxEvidence, Payload: []byte(`{}`), CreatedAt: time.Now().UTC()}
	if err := outbox.Enqueue(message); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ForwardOutbox(context.Background(), outbox, 1); err == nil {
		t.Fatal("rejected worker message was acknowledged")
	}
	queued, err := outbox.Peek()
	if err != nil || queued.ID != message.ID {
		t.Fatalf("rejected worker message was removed: %#v %v", queued, err)
	}
}
