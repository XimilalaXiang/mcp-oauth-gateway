package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	dataFile := os.Getenv("GATEWAY_DATA_FILE")
	if dataFile == "" {
		dataFile = "/data/gateway-state.json"
	}
	store := NewStore(dataFile)
	jwtMgr := NewJWTManager(cfg.Auth.JWTSecret, strings.TrimRight(cfg.Server.BaseURL, "/"), cfg.Auth.TokenTTL)

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-protected-resource", handleProtectedResourceMetadata(cfg))
	mux.HandleFunc("/.well-known/oauth-authorization-server", handleAuthServerMetadata(cfg))

	mux.HandleFunc("/register", handleRegister(store))
	mux.HandleFunc("/authorize", handleAuthorize(cfg, store))
	mux.HandleFunc("/token", handleToken(cfg, store, jwtMgr))

	mux.HandleFunc("/mcp/", handleMCPProxy(cfg, jwtMgr))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","backends":%d}`, len(cfg.Backends))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			backends := make([]string, 0, len(cfg.Backends))
			for k := range cfg.Backends {
				backends = append(backends, k)
			}
			fmt.Fprintf(w, `{"service":"mcp-oauth-gateway","version":"1.0.0","backends":%d}`, len(backends))
			return
		}
		http.NotFound(w, r)
	})

	log.Printf("MCP OAuth Gateway starting on :%s", cfg.Server.Port)
	log.Printf("Base URL: %s", cfg.Server.BaseURL)
	for name, b := range cfg.Backends {
		log.Printf("  Backend [%s]: %s -> %s (%s)", name, b.Name, b.Upstream, b.Transport)
	}

	if err := http.ListenAndServe(":"+cfg.Server.Port, mux); err != nil {
		log.Fatal(err)
	}
}
