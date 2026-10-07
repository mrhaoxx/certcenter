// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Topics the UI can subscribe to. A signal carries no payload: the client
// re-fetches whatever it needs, which keeps the stream trivial and avoids
// leaking data to a subscriber that should not see it.
const (
	TopicCertificates = "certificates"
	TopicRuns         = "runs"
	TopicDeployments  = "deployments"
	TopicLogs         = "logs"
	TopicAccounts     = "accounts"
	TopicProviders    = "providers"
	TopicTargets      = "targets"
)

// Broker fans topic signals out to the connected SSE clients.
//
// Issuance takes a minute or more, so without this the UI could only poll —
// which is exactly what the Rust frontend had to do.
type Broker struct {
	mu          sync.RWMutex
	subscribers map[chan string]map[string]bool
}

func NewBroker() *Broker {
	return &Broker{subscribers: map[chan string]map[string]bool{}}
}

// Subscribe registers for the given topics. The returned cancel function
// must be called to release the subscription.
func (b *Broker) Subscribe(topics []string) (<-chan string, func()) {
	// Buffered so a slow client cannot block a publisher.
	ch := make(chan string, 16)
	set := map[string]bool{}
	for _, t := range topics {
		set[t] = true
	}

	b.mu.Lock()
	b.subscribers[ch] = set
	b.mu.Unlock()

	return ch, func() {
		b.mu.Lock()
		if _, ok := b.subscribers[ch]; ok {
			delete(b.subscribers, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}

// Publish signals a topic. It never blocks: a subscriber whose buffer is
// full is simply skipped, because these are hints to refetch rather than
// data that must arrive.
func (b *Broker) Publish(topic string) {
	if b == nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch, topics := range b.subscribers {
		if !topics[topic] {
			continue
		}
		select {
		case ch <- topic:
		default:
		}
	}
}

// handleEvents streams topic signals as Server-Sent Events.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "streaming unsupported", nil)
		return
	}

	topics := splitTopics(r.URL.Query().Get("topics"))
	if len(topics) == 0 {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "no topics requested", nil)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Proxies that buffer would defeat the whole point of the stream.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch, cancel := s.Events.Subscribe(topics)
	defer cancel()

	// A periodic comment keeps intermediaries from timing the idle
	// connection out.
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case topic, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: 1\n\n", topic)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func splitTopics(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}
