package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type sseSession struct {
	mu         sync.Mutex
	sessionID  string
	messageURL string
	sseResp    *http.Response
	scanner    *bufio.Scanner
	backend    BackendConfig
	upstream   string
	client     *http.Client
	ready      chan struct{}
	closed     bool
}

func newSSESession(backend BackendConfig) *sseSession {
	return &sseSession{
		backend: backend,
		upstream: strings.TrimRight(backend.Upstream, "/"),
		client:  &http.Client{Timeout: 0},
		ready:   make(chan struct{}),
	}
}

func (s *sseSession) connect() error {
	req, err := http.NewRequest("GET", s.upstream+"/sse", nil)
	if err != nil {
		return fmt.Errorf("create SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	if s.backend.AuthHeader != "" {
		req.Header.Set("Authorization", s.backend.AuthHeader)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connect: %w", err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return fmt.Errorf("SSE returned %d", resp.StatusCode)
	}

	s.sseResp = resp
	s.scanner = bufio.NewScanner(resp.Body)
	s.scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	go s.readEndpoint()
	return nil
}

func (s *sseSession) readEndpoint() {
	var eventType string
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			if eventType == "endpoint" {
				s.mu.Lock()
				if strings.HasPrefix(data, "/") {
					s.messageURL = s.upstream + data
				} else {
					s.messageURL = data
				}
				s.mu.Unlock()
				close(s.ready)
				return
			}
		}
	}
}

func (s *sseSession) waitReady(timeout time.Duration) error {
	select {
	case <-s.ready:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for SSE endpoint")
	}
}

func (s *sseSession) sendMessage(body []byte) ([]byte, error) {
	s.mu.Lock()
	msgURL := s.messageURL
	s.mu.Unlock()

	req, err := http.NewRequest("POST", msgURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create message request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.backend.AuthHeader != "" {
		req.Header.Set("Authorization", s.backend.AuthHeader)
	}

	httpClient := &http.Client{Timeout: 2 * time.Minute}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 || resp.StatusCode == 200 {
		// For SSE backends, the response comes via SSE stream, not the POST response
		// 202 = accepted, response will come via SSE
		// Read from SSE stream for the actual response
		return s.readResponse()
	}

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("message failed with %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (s *sseSession) readResponse() ([]byte, error) {
	var eventType string
	deadline := time.After(2 * time.Minute)

	for {
		select {
		case <-deadline:
			return nil, fmt.Errorf("timeout reading SSE response")
		default:
		}

		if !s.scanner.Scan() {
			if err := s.scanner.Err(); err != nil {
				return nil, fmt.Errorf("SSE read error: %w", err)
			}
			return nil, fmt.Errorf("SSE stream ended")
		}

		line := s.scanner.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			if eventType == "message" {
				return []byte(data), nil
			}
		}
	}
}

func (s *sseSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.sseResp != nil {
		s.sseResp.Body.Close()
	}
}

func handleStreamableHTTPBridge(cfg *Config, jwtMgr *JWTManager) http.HandlerFunc {
	type sessionEntry struct {
		session   *sseSession
		createdAt time.Time
	}
	var sessionsMu sync.Mutex
	sessions := make(map[string]*sessionEntry)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			sessionsMu.Lock()
			for k, v := range sessions {
				if time.Since(v.createdAt) > 30*time.Minute {
					v.session.close()
					delete(sessions, k)
				}
			}
			sessionsMu.Unlock()
		}
	}()

	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/mcp/"), "/", 2)
		if len(parts) == 0 || parts[0] == "" {
			httpError(w, http.StatusNotFound, "not_found", "backend not specified")
			return
		}

		backendName := parts[0]
		backend, ok := cfg.Backends[backendName]
		if !ok {
			httpError(w, http.StatusNotFound, "not_found", fmt.Sprintf("backend '%s' not found", backendName))
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			baseURL := strings.TrimRight(cfg.Server.BaseURL, "/")
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer realm="mcp-gateway", resource_metadata="%s/.well-known/oauth-protected-resource"`,
				baseURL,
			))
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized","error_description":"Bearer token required"}`))
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		_, err := jwtMgr.Validate(token)
		if err != nil {
			baseURL := strings.TrimRight(cfg.Server.BaseURL, "/")
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer error="invalid_token", resource_metadata="%s/.well-known/oauth-protected-resource"`,
				baseURL,
			))
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_token","error_description":"token validation failed"}`))
			return
		}

		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"name":"%s","version":"1.0.0","transport":"streamable-http"}`, backend.Name)
			return
		}

		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpError(w, http.StatusBadRequest, "invalid_request", "failed to read body")
			return
		}

		var rpcReq struct {
			JSONRPC string `json:"jsonrpc"`
			ID      any    `json:"id"`
			Method  string `json:"method"`
		}
		if err := json.Unmarshal(body, &rpcReq); err != nil {
			httpError(w, http.StatusBadRequest, "invalid_request", "invalid JSON-RPC")
			return
		}

		sessionKey := fmt.Sprintf("%s-%s", backendName, token[:16])

		if rpcReq.Method == "initialize" {
			sessionsMu.Lock()
			if old, ok := sessions[sessionKey]; ok {
				old.session.close()
				delete(sessions, sessionKey)
			}
			sessionsMu.Unlock()
		}

		sessionsMu.Lock()
		entry, exists := sessions[sessionKey]
		sessionsMu.Unlock()

		if !exists {
			sess := newSSESession(backend)
			if err := sess.connect(); err != nil {
				log.Printf("[BRIDGE] SSE connect failed for %s: %v", backendName, err)
				httpError(w, http.StatusBadGateway, "bad_gateway", "failed to connect to backend SSE")
				return
			}

			if err := sess.waitReady(10 * time.Second); err != nil {
				sess.close()
				log.Printf("[BRIDGE] SSE endpoint timeout for %s: %v", backendName, err)
				httpError(w, http.StatusBadGateway, "bad_gateway", "backend SSE did not provide endpoint")
				return
			}

			entry = &sessionEntry{session: sess, createdAt: time.Now()}
			sessionsMu.Lock()
			sessions[sessionKey] = entry
			sessionsMu.Unlock()

			log.Printf("[BRIDGE] New SSE session for %s, message URL: %s", backendName, sess.messageURL)
		}

		respData, err := entry.session.sendMessage(body)
		if err != nil {
			log.Printf("[BRIDGE] message failed for %s: %v, reconnecting", backendName, err)

			sessionsMu.Lock()
			entry.session.close()
			delete(sessions, sessionKey)
			sessionsMu.Unlock()

			sess := newSSESession(backend)
			if err := sess.connect(); err != nil {
				httpError(w, http.StatusBadGateway, "bad_gateway", "reconnect failed")
				return
			}
			if err := sess.waitReady(10 * time.Second); err != nil {
				sess.close()
				httpError(w, http.StatusBadGateway, "bad_gateway", "reconnect endpoint timeout")
				return
			}

			entry = &sessionEntry{session: sess, createdAt: time.Now()}
			sessionsMu.Lock()
			sessions[sessionKey] = entry
			sessionsMu.Unlock()

			respData, err = entry.session.sendMessage(body)
			if err != nil {
				httpError(w, http.StatusBadGateway, "bad_gateway", "retry also failed: "+err.Error())
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(respData)
	}
}
