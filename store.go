package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type OAuthClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	CreatedAt    time.Time `json:"-"`
}

type AuthCode struct {
	Code         string
	ClientID     string
	RedirectURI  string
	CodeChallenge string
	CodeChallengeMethod string
	UserID       string
	Scopes       []string
	ExpiresAt    time.Time
	Used         bool
}

type RefreshToken struct {
	Token    string
	ClientID string
	UserID   string
	Scopes   []string
	CreatedAt time.Time
}

type Store struct {
	mu            sync.RWMutex
	clients       map[string]*OAuthClient
	codes         map[string]*AuthCode
	refreshTokens map[string]*RefreshToken
}

func NewStore() *Store {
	s := &Store{
		clients:       make(map[string]*OAuthClient),
		codes:         make(map[string]*AuthCode),
		refreshTokens: make(map[string]*RefreshToken),
	}
	go s.cleanup()
	return s
}

func (s *Store) SaveClient(c *OAuthClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
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
		cutoff := now.Add(-7 * 24 * time.Hour)
		for k, c := range s.clients {
			if c.CreatedAt.Before(cutoff) {
				delete(s.clients, k)
			}
		}
		// Refresh tokens never expire by default (persist until revoked or server restart)
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
