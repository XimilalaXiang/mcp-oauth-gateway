package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func handleRegister(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
			return
		}

		var req struct {
			RedirectURIs            []string `json:"redirect_uris"`
			ClientName              string   `json:"client_name"`
			GrantTypes              []string `json:"grant_types"`
			ResponseTypes           []string `json:"response_types"`
			TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}

		if len(req.RedirectURIs) == 0 {
			httpError(w, http.StatusBadRequest, "invalid_request", "redirect_uris required")
			return
		}
		if len(req.GrantTypes) == 0 {
			req.GrantTypes = []string{"authorization_code"}
		}
		if len(req.ResponseTypes) == 0 {
			req.ResponseTypes = []string{"code"}
		}
		if req.TokenEndpointAuthMethod == "" {
			req.TokenEndpointAuthMethod = "none"
		}

		client := &OAuthClient{
			ClientID:                randomString(16),
			ClientName:              req.ClientName,
			RedirectURIs:            req.RedirectURIs,
			GrantTypes:              req.GrantTypes,
			ResponseTypes:           req.ResponseTypes,
			TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
			CreatedAt:               time.Now(),
		}
		store.SaveClient(client)

		log.Printf("[DCR] Registered client: %s (%s)", client.ClientID, client.ClientName)

		resp := map[string]any{
			"client_id":                  client.ClientID,
			"client_name":               client.ClientName,
			"redirect_uris":             client.RedirectURIs,
			"grant_types":               client.GrantTypes,
			"response_types":            client.ResponseTypes,
			"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}
}

func handleAuthorize(cfg *Config, store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method == http.MethodGet {
			clientID := r.URL.Query().Get("client_id")
			redirectURI := r.URL.Query().Get("redirect_uri")
			responseType := r.URL.Query().Get("response_type")
			scope := r.URL.Query().Get("scope")
			state := r.URL.Query().Get("state")
			codeChallenge := r.URL.Query().Get("code_challenge")
			codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

			if responseType != "code" {
				httpError(w, http.StatusBadRequest, "unsupported_response_type", "only 'code' supported")
				return
			}
			if codeChallenge == "" || codeChallengeMethod != "S256" {
				httpError(w, http.StatusBadRequest, "invalid_request", "PKCE S256 required")
				return
			}

			client := store.GetClient(clientID)
			if client == nil {
				if isValidURL(clientID) {
					client = &OAuthClient{
						ClientID:     clientID,
						RedirectURIs: []string{redirectURI},
						CreatedAt:    time.Now(),
					}
					store.SaveClient(client)
					log.Printf("[CIMD] Auto-registered client from URL: %s", clientID)
				} else {
					httpError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
					return
				}
			}

			if !validRedirectURI(client.RedirectURIs, redirectURI) {
				httpError(w, http.StatusBadRequest, "invalid_request", "redirect_uri mismatch")
				return
			}

			scopes := strings.Fields(scope)
			if len(scopes) == 0 {
				scopes = []string{"mcp:read", "mcp:write"}
			}

			data := loginData{
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				ResponseType:        responseType,
				ScopeRaw:            scope,
				Scopes:              scopes,
				State:               state,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			loginTmpl.Execute(w, data)
			return
		}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				httpError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
				return
			}
			clientID := r.FormValue("client_id")
			redirectURI := r.FormValue("redirect_uri")
			state := r.FormValue("state")
			scope := r.FormValue("scope")
			codeChallenge := r.FormValue("code_challenge")
			codeChallengeMethod := r.FormValue("code_challenge_method")
			password := r.FormValue("password")

			if !checkPassword(cfg, password) {
				scopes := strings.Fields(scope)
				if len(scopes) == 0 {
					scopes = []string{"mcp:read", "mcp:write"}
				}
				data := loginData{
					ClientID:            clientID,
					RedirectURI:         redirectURI,
					ResponseType:        "code",
					ScopeRaw:            scope,
					Scopes:              scopes,
					State:               state,
					CodeChallenge:       codeChallenge,
					CodeChallengeMethod: codeChallengeMethod,
					Error:               "Invalid password. Please try again.",
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				loginTmpl.Execute(w, data)
				return
			}

			code := randomString(32)
			ac := &AuthCode{
				Code:                code,
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
				UserID:              "owner",
				Scopes:              strings.Fields(scope),
				ExpiresAt:           time.Now().Add(10 * time.Minute),
			}
			store.SaveCode(ac)

			log.Printf("[AUTH] Issued authorization code for client: %s", clientID)

			redirectURL, err := url.Parse(redirectURI)
			if err != nil {
				httpError(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
				return
			}
			q := redirectURL.Query()
			q.Set("code", code)
			if state != "" {
				q.Set("state", state)
			}
			redirectURL.RawQuery = q.Encode()

			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return
		}

		httpError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET or POST required")
	}
}

func handleToken(cfg *Config, store *Store, jwtMgr *JWTManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
			return
		}

		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
			return
		}
		grantType := r.FormValue("grant_type")

		if grantType != "authorization_code" {
			httpError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code supported")
			return
		}

		code := r.FormValue("code")
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		codeVerifier := r.FormValue("code_verifier")

		ac := store.GetCode(code)
		if ac == nil {
			httpError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
			return
		}

		if ac.ClientID != clientID {
			httpError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
			return
		}
		if ac.RedirectURI != redirectURI {
			httpError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		}

		if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, codeVerifier) {
			httpError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}

		store.MarkCodeUsed(code)

		accessToken, err := jwtMgr.Issue(ac.UserID, clientID, ac.Scopes)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
			return
		}

		log.Printf("[TOKEN] Issued access token for client: %s", clientID)

		resp := map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   int(cfg.Auth.TokenTTL.Seconds()),
			"scope":        strings.Join(ac.Scopes, " "),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(resp)
	}
}

func verifyPKCE(challenge, method, verifier string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	if method != "S256" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func validRedirectURI(registered []string, uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}

	host := parsed.Hostname()

	// RFC 8252: allow localhost and 127.0.0.1 with any port (for Claude Code)
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}

	// Allow Claude.ai callback URL
	if host == "claude.ai" && strings.HasPrefix(parsed.Path, "/api/mcp/") {
		return true
	}

	for _, r := range registered {
		if r == uri {
			return true
		}
		rp, err := url.Parse(r)
		if err != nil {
			continue
		}
		if rp.Scheme == parsed.Scheme && rp.Host == parsed.Host && rp.Path == parsed.Path {
			return true
		}
	}
	return false
}

func isValidURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept")
}

func httpError(w http.ResponseWriter, status int, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}
