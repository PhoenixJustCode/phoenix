// Package config reads service settings from the environment.
package config

import "errors"

const (
	defaultListenAddr = "127.0.0.1:8000"
	defaultGeoBaseURL = "https://ipapi.co"
)

// Config is the runtime configuration of the service.
type Config struct {
	DatabaseURL string
	ListenAddr  string
	GeoBaseURL  string
}

// Load builds Config from getenv, applying defaults for optional values.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		DatabaseURL: getenv("DATABASE_URL"),
		ListenAddr:  getenv("LISTEN_ADDR"),
		GeoBaseURL:  getenv("GEO_BASE_URL"),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListenAddr
	}
	if cfg.GeoBaseURL == "" {
		cfg.GeoBaseURL = defaultGeoBaseURL
	}
	return cfg, nil
}
