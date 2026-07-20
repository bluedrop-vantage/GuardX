package evidence

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// HTTPEmitter fires events at the Control API's /v1/evidence/events endpoint.
//
// Design (spec §4.4): fire-and-forget; the response path never waits on this.
//   - Emit() drops events into a bounded in-memory queue.
//   - A worker goroutine flushes the queue in batches on a short interval.
//   - If the network call fails, the batch is appended to a JSONL spool file
//     on local disk. A separate worker replays the spool once the API recovers.
//   - Emit() drops to spool directly if the queue is full — the payload is
//     never lost while disk has room, and we never block the caller.
type HTTPEmitter struct {
	BaseURL   string
	APIKey    string
	SpoolPath string
	Logger    *slog.Logger
	Client    *http.Client

	BatchSize     int
	FlushInterval time.Duration

	queue chan Event

	spoolMu sync.Mutex
	spoolFP *os.File

	stop chan struct{}
	wg   sync.WaitGroup
}

// NewHTTPEmitter constructs an emitter. Call Start once, and Close on shutdown.
func NewHTTPEmitter(baseURL, apiKey, spoolPath string, logger *slog.Logger) *HTTPEmitter {
	return &HTTPEmitter{
		BaseURL:       baseURL,
		APIKey:        apiKey,
		SpoolPath:     spoolPath,
		Logger:        logger,
		Client:        &http.Client{Timeout: 5 * time.Second},
		BatchSize:     50,
		FlushInterval: 500 * time.Millisecond,
		queue:         make(chan Event, 4096),
		stop:          make(chan struct{}),
	}
}

// Start launches background workers. Idempotent.
func (e *HTTPEmitter) Start() error {
	if e.SpoolPath == "" {
		return fmt.Errorf("HTTPEmitter: SpoolPath required")
	}
	if err := os.MkdirAll(filepath.Dir(e.SpoolPath), 0o750); err != nil {
		return err
	}
	fp, err := os.OpenFile(e.SpoolPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	e.spoolFP = fp

	e.wg.Add(2)
	go e.flushLoop()
	go e.replayLoop()
	return nil
}

// Close drains best-effort and stops workers.
func (e *HTTPEmitter) Close() error {
	close(e.stop)
	e.wg.Wait()
	if e.spoolFP != nil {
		_ = e.spoolFP.Close()
	}
	return nil
}

// Emit enqueues without blocking. When the queue is full, the event goes to
// the spool. Callers never wait on the network.
func (e *HTTPEmitter) Emit(evt Event) {
	if evt.EventID == "" {
		evt.EventID = newEventID()
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}
	select {
	case e.queue <- evt:
	default:
		// Queue full — spool synchronously (still doesn't hit the network).
		e.spoolAppend([]Event{evt})
		e.Logger.Warn("evidence queue full — spooled event", "event_id", evt.EventID)
	}
}

func (e *HTTPEmitter) flushLoop() {
	defer e.wg.Done()
	tick := time.NewTicker(e.FlushInterval)
	defer tick.Stop()

	batch := make([]Event, 0, e.BatchSize)
	drain := func(reason string) {
		if len(batch) == 0 {
			return
		}
		if err := e.postBatch(context.Background(), batch); err != nil {
			e.Logger.Warn("evidence post failed — spooling", "err", err, "n", len(batch), "reason", reason)
			e.spoolAppend(batch)
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-e.stop:
			// Drain the queue on shutdown, best effort.
			for {
				select {
				case evt := <-e.queue:
					batch = append(batch, evt)
					if len(batch) == e.BatchSize {
						drain("shutdown-batch")
					}
				default:
					drain("shutdown-flush")
					return
				}
			}
		case <-tick.C:
			drain("tick")
		case evt := <-e.queue:
			batch = append(batch, evt)
			if len(batch) >= e.BatchSize {
				drain("batch-full")
			}
		}
	}
}

func (e *HTTPEmitter) postBatch(ctx context.Context, events []Event) error {
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", e.BaseURL+"/v1/evidence/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GuardX-Key", e.APIKey)
	resp, err := e.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, body)
	}
	return nil
}

func (e *HTTPEmitter) spoolAppend(events []Event) {
	e.spoolMu.Lock()
	defer e.spoolMu.Unlock()
	if e.spoolFP == nil {
		return
	}
	enc := json.NewEncoder(e.spoolFP)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			e.Logger.Error("evidence spool write failed", "err", err)
			return
		}
	}
	_ = e.spoolFP.Sync()
}

// replayLoop periodically drains the spool file back into the queue once the
// upstream is healthy again. Simple strategy: try one line at a time.
func (e *HTTPEmitter) replayLoop() {
	defer e.wg.Done()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-tick.C:
			e.replayOnce()
		}
	}
}

func (e *HTTPEmitter) replayOnce() {
	e.spoolMu.Lock()
	defer e.spoolMu.Unlock()

	// Close append handle, read spool contents, truncate, then write back what
	// we couldn't post. Safe because callers hold the mutex.
	if e.spoolFP != nil {
		_ = e.spoolFP.Close()
		e.spoolFP = nil
	}
	spool, err := os.OpenFile(e.SpoolPath, os.O_RDONLY, 0o640)
	if err != nil {
		e.reopenAppend()
		return
	}
	var events []Event
	sc := bufio.NewScanner(spool)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		events = append(events, ev)
	}
	_ = spool.Close()

	if len(events) == 0 {
		_ = os.Truncate(e.SpoolPath, 0)
		e.reopenAppend()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.postBatch(ctx, events); err != nil {
		e.Logger.Info("evidence replay: upstream still down", "n", len(events))
		e.reopenAppend()
		return
	}

	// Success — clear the spool.
	_ = os.Truncate(e.SpoolPath, 0)
	e.reopenAppend()
	e.Logger.Info("evidence replay: drained spool", "n", len(events))
}

func (e *HTTPEmitter) reopenAppend() {
	fp, err := os.OpenFile(e.SpoolPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		e.Logger.Error("evidence: reopen spool failed", "err", err)
		return
	}
	e.spoolFP = fp
}
