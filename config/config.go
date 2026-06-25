package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const DefaultConfigFile = "config.yaml"

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Auth    AuthConfig    `yaml:"auth"`
	Database DatabaseConfig `yaml:"database"`
	Scanner ScannerConfig `yaml:"scanner"`
}

type ServerConfig struct {
	Port     int    `yaml:"port"`
	BasePath string `yaml:"base_path"`
}

type AuthConfig struct {
	Password string `yaml:"password"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type ScannerConfig struct {
	IntervalSeconds int `yaml:"interval_seconds"`
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Port:     9300,
			BasePath: "",
		},
		Auth: AuthConfig{
			Password: "admin",
		},
		Database: DatabaseConfig{
			Path: "./data/ipgard.db",
		},
		Scanner: ScannerConfig{
			IntervalSeconds: 10,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := Save(path, cfg); err != nil {
			return nil, fmt.Errorf("create default config: %w", err)
		}
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func Save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (c *Config) ListenAddr() string {
	return fmt.Sprintf(":%d", c.Server.Port)
}

func (c *Config) NormalizedBasePath() string {
	p := c.Server.BasePath
	if p == "" || p == "/" {
		return ""
	}
	if p[0] != '/' {
		p = "/" + p
	}
	if len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}
