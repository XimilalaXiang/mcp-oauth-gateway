package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func handleProtectedResourceMetadata(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		baseURL := strings.TrimRight(cfg.Server.BaseURL, "/")
		meta := map[string]any{
			"resource":                baseURL + "/",
			"authorization_servers":   []string{baseURL},
			"scopes_supported":       []string{"mcp:read", "mcp:write"},
			"bearer_methods_supported": []string{"header"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(meta)
	}
}

func handleAuthServerMetadata(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		baseURL := strings.TrimRight(cfg.Server.BaseURL, "/")
		meta := map[string]any{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/authorize",
			"token_endpoint":                        baseURL + "/token",
			"registration_endpoint":                 baseURL + "/register",
			"scopes_supported":                      []string{"mcp:read", "mcp:write"},
			"response_types_supported":              []string{"code"},
			"response_modes_supported":              []string{"query"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"code_challenge_methods_supported":      []string{"S256"},
			"client_id_metadata_document_supported": true,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(meta)
	}
}
