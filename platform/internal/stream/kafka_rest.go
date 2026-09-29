package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

// kafkaRESTSink produces API events to Kafka through the Confluent REST Proxy.
// Using the REST proxy keeps the platform free of any native Kafka client
// dependency: it is a plain HTTP POST of newline-free JSON.
type kafkaRESTSink struct {
	url    string // {rest}/topics/{topic}
	target string
	client *http.Client

	queue  chan shared.APIEvent
	cancel context.CancelFunc
	wg     sync.WaitGroup

	batchSize     int
	flushInterval time.Duration
	published     uint64
	failed        uint64
	dropped       uint64

	mu        sync.Mutex
	lastError string
}

type kafkaRecord struct {
	Key   string          `json:"key,omitempty"`
	Value json.RawMessage `json:"value"`
}

type kafkaPayload struct {
	Records []kafkaRecord `json:"records"`
}

func newKafkaRESTSink(cfg Config) *kafkaRESTSink {
	ctx, cancel := context.WithCancel(context.Background())
	s := &kafkaRESTSink{
		url:           fmt.Sprintf("%s/topics/%s", cfg.KafkaRESTURL, cfg.KafkaTopic),
		target:        cfg.KafkaRESTURL + " · " + cfg.KafkaTopic,
		client:        &http.Client{Timeout: 10 * time.Second},
		queue:         make(chan shared.APIEvent, cfg.BufferSize),
		cancel:        cancel,
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
	}
	s.wg.Add(1)
	go s.loop(ctx)
	logger.L().Infof("stream: Kafka REST sink enabled → %s", s.url)
	return s
}

func (s *kafkaRESTSink) Publish(evt shared.APIEvent) {
	select {
	case s.queue <- evt:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

func (s *kafkaRESTSink) loop(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	batch := make([]shared.APIEvent, 0, s.batchSize)
	drain := func() {
		if len(batch) == 0 {
			return
		}
		s.send(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// best-effort drain of whatever is already queued
			for {
				select {
				case evt := <-s.queue:
					batch = append(batch, evt)
					if len(batch) >= s.batchSize {
						drain()
					}
				default:
					drain()
					return
				}
			}
		case evt := <-s.queue:
			batch = append(batch, evt)
			if len(batch) >= s.batchSize {
				drain()
			}
		case <-ticker.C:
			drain()
		}
	}
}

func (s *kafkaRESTSink) send(events []shared.APIEvent) {
	payload := kafkaPayload{Records: make([]kafkaRecord, 0, len(events))}
	for i := range events {
		value, err := json.Marshal(&events[i])
		if err != nil {
			atomic.AddUint64(&s.failed, 1)
			continue
		}
		payload.Records = append(payload.Records, kafkaRecord{
			Key:   kafkaKey(events[i]),
			Value: value,
		})
	}
	if len(payload.Records) == 0 {
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.recordFailure(len(payload.Records), err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		s.recordFailure(len(payload.Records), err)
		return
	}
	req.Header.Set("Content-Type", "application/vnd.kafka.json.v2+json")
	req.Header.Set("Accept", "application/vnd.kafka.v2+json")

	resp, err := s.client.Do(req)
	if err != nil {
		s.recordFailure(len(payload.Records), err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		s.recordFailure(len(payload.Records), fmt.Errorf("kafka rest status %d: %s", resp.StatusCode, string(msg)))
		return
	}
	io.Copy(io.Discard, resp.Body)
	atomic.AddUint64(&s.published, uint64(len(payload.Records)))
}

func (s *kafkaRESTSink) recordFailure(n int, err error) {
	atomic.AddUint64(&s.failed, uint64(n))
	s.mu.Lock()
	s.lastError = err.Error()
	s.mu.Unlock()
	logger.L().Warnf("stream: kafka publish failed (%d events): %v", n, err)
}

func (s *kafkaRESTSink) Stats() SinkStats {
	s.mu.Lock()
	lastErr := s.lastError
	s.mu.Unlock()
	return SinkStats{
		Enabled:   true,
		Name:      "kafka-rest",
		Target:    s.target,
		Published: atomic.LoadUint64(&s.published),
		Failed:    atomic.LoadUint64(&s.failed),
		Dropped:   atomic.LoadUint64(&s.dropped),
		Buffered:  len(s.queue),
		LastError: lastErr,
	}
}

func (s *kafkaRESTSink) Close() error {
	s.cancel()
	s.wg.Wait()
	return nil
}

func kafkaKey(evt shared.APIEvent) string {
	if evt.AgentID != "" {
		return evt.AgentID
	}
	if evt.Application.Host != "" {
		return evt.Application.Host
	}
	return evt.Network.SrcIP
}
