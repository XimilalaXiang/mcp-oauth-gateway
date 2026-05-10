package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Port    string `yaml:"port"`
	BaseURL string `yaml:"base_url"`
}

type AuthConfig struct {
	Password   string `yaml:"password"`
	JWTSecret  string `yaml:"jwt_secret"`
	TokenTTLStr string `yaml:"token_ttl"`
	TokenTTL   time.Duration
}

type BackendConfig struct {
	Name       string `yaml:"name"`
	Upstream   string `yaml:"upstream"`
	Transport  string `yaml:"transport"`
	AuthHeader string `yaml:"auth_header"`
}

type Config struct {
	Server   ServerConfig             `yaml:"server"`
	Auth     AuthConfig               `yaml:"auth"`
	Backends map[string]BackendConfig `yaml:"backends"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Server.Port == "" {
		cfg.Server.Port = "8800"
	}
	if cfg.Auth.TokenTTLStr != "" {
		d, err := time.ParseDuration(cfg.Auth.TokenTTLStr)
		if err != nil {
			return nil, fmt.Errorf("invalid token_ttl: %w", err)
		}
		cfg.Auth.TokenTTL = d
	}
	if cfg.Auth.TokenTTL == 0 {
		cfg.Auth.TokenTTL = 24 * time.Hour
	}

	if v := os.Getenv("GATEWAY_PORT"); v != "" {
		cfg.Server.Port = v
	}
	if v := os.Getenv("GATEWAY_BASE_URL"); v != "" {
		cfg.Server.BaseURL = v
	}
	if v := os.Getenv("GATEWAY_PASSWORD"); v != "" {
		cfg.Auth.Password = v
	}
	if v := os.Getenv("GATEWAY_JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}

	if cfg.Server.BaseURL == "" {
		return nil, fmt.Errorf("server.base_url is required")
	}
	if cfg.Auth.Password == "" {
		return nil, fmt.Errorf("auth.password is required")
	}
	if cfg.Auth.JWTSecret == "" {
		return nil, fmt.Errorf("auth.jwt_secret is required")
	}

	return &cfg, nil
}
