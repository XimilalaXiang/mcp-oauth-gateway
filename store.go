package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type OAuthClient struct {
	ClientID               string   `json:"client_id"`
	ClientName             string   `json:"client_name,omitempty"`
	RedirectURIs           []string `json:"redirect_uris"`
	GrantTypes             []string `json:"grant_types"`
	ResponseTypes          []string `json:"response_types"`
	TokenEndpointAuthMethod string  `json:"token_endpoint_auth_method"`
	CreatedAt              time.Time `json:"created_at"`
}

type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
	Scopes              []string
	ExpiresAt           time.Time
	Used                bool
}

type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
}

type persistedState struct {
	Clients       map[string]*OAuthClient  `json:"clients"`
	RefreshTokens map[string]*RefreshToken `json:"refresh_tokens"`
}

type Store struct {
	mu            sync.RWMutex
	clients       map[string]*OAuthClient
	codes         map[string]*AuthCode
	refreshTokens map[string]*RefreshToken
	dataFile      string
}

func NewStore(dataFile string) *Store {
	s := &Store{
		clients:       make(map[string]*OAuthClient),
		codes:         make(map[string]*AuthCode),
		refreshTokens: make(map[string]*RefreshToken),
		dataFile:      dataFile,
	}
	s.load()
	go s.cleanup()
	return s
}

func (s *Store) SaveClient(c *OAuthClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
	s.persistLocked()
}

func (s *Store) GetClient(id string) *OAuthClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients[id]
}

func (s *Store) SaveCode(ac *AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[ac.Code] = ac
}

func (s *Store) GetCode(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.codes[code]
	if !ok || ac.Used || time.Now().After(ac.ExpiresAt) {
		return nil
	}
	return ac
}

func (s *Store) MarkCodeUsed(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ac, ok := s.codes[code]; ok {
		ac.Used = true
	}
}

func (s *Store) SaveRefreshToken(rt *RefreshToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[rt.Token] = rt
	s.persistLocked()
}

func (s *Store) GetRefreshToken(token string) *RefreshToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refreshTokens[token]
}

func (s *Store) DeleteRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, token)
	s.persistLocked()
}

func (s *Store) load() {
	if s.dataFile == "" {
		return
	}
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[STORE] Failed to read data file: %v", err)
		}
		return
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[STORE] Failed to parse data file: %v", err)
		return
	}
	if state.Clients != nil {
		s.clients = state.Clients
	}
	if state.RefreshTokens != nil {
		s.refreshTokens = state.RefreshTokens
	}
	log.Printf("[STORE] Loaded %d clients, %d refresh tokens from %s", len(s.clients), len(s.refreshTokens), s.dataFile)
}

// persistLocked writes state to disk. Caller must hold s.mu.
func (s *Store) persistLocked() {
	if s.dataFile == "" {
		return
	}
	state := persistedState{
		Clients:       s.clients,
		RefreshTokens: s.refreshTokens,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("[STORE] Failed to marshal state: %v", err)
		return
	}

	dir := filepath.Dir(s.dataFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("[STORE] Failed to create data dir: %v", err)
		return
	}

	tmpFile := s.dataFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		log.Printf("[STORE] Failed to write temp file: %v", err)
		return
	}
	if err := os.Rename(tmpFile, s.dataFile); err != nil {
		log.Printf("[STORE] Failed to rename data file: %v", err)
	}
}

func (s *Store) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, ac := range s.codes {
			if now.After(ac.ExpiresAt.Add(5 * time.Minute)) {
				delete(s.codes, k)
			}
		}
		cutoff := now.Add(-30 * 24 * time.Hour)
		for k, c := range s.clients {
			if c.CreatedAt.Before(cutoff) {
				delete(s.clients, k)
			}
		}
		s.mu.Unlock()
	}
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
