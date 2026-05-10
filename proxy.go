package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func handleMCPProxy(cfg *Config, jwtMgr *JWTManager) http.HandlerFunc {
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

		remainingPath := ""
		if len(parts) > 1 {
			remainingPath = "/" + parts[1]
		}

		upstreamURL := strings.TrimRight(backend.Upstream, "/") + remainingPath
		if r.URL.RawQuery != "" {
			upstreamURL += "?" + r.URL.RawQuery
		}

		proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
		if err != nil {
			httpError(w, http.StatusBadGateway, "bad_gateway", "failed to create upstream request")
			return
		}

		for key, vals := range r.Header {
			lower := strings.ToLower(key)
			if lower == "host" || lower == "authorization" {
				continue
			}
			for _, v := range vals {
				proxyReq.Header.Add(key, v)
			}
		}

		if backend.AuthHeader != "" {
			proxyReq.Header.Set("Authorization", backend.AuthHeader)
		}

		isSSE := strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
			backend.Transport == "sse"

		client := &http.Client{Timeout: 5 * time.Minute}
		if isSSE {
			client.Timeout = 0
		}

		resp, err := client.Do(proxyReq)
		if err != nil {
			log.Printf("[PROXY] upstream error for %s: %v", backendName, err)
			httpError(w, http.StatusBadGateway, "bad_gateway", "upstream request failed")
			return
		}
		defer resp.Body.Close()

		for key, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(resp.StatusCode)

		if isSSE || strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			flusher, ok := w.(http.Flusher)
			if !ok {
				io.Copy(w, resp.Body)
				return
			}
			buf := make([]byte, 4096)
			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					w.Write(buf[:n])
					flusher.Flush()
				}
				if err != nil {
					return
				}
			}
		}

		io.Copy(w, resp.Body)
	}
}
