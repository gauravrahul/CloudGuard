package config

import (
	"encoding/json"
	"fmt"
	"intrualert/types"
	"os"
	"path/filepath"
	"strings"
)

// LoadConfig loads configuration from the specified path
func LoadConfig() (*types.Config, error) {
	configPath := filepath.Join("config", "config.json")
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg types.Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, err
	}

	// Set defaults if not specified
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.SignatureFile == "" {
		cfg.SignatureFile = "config/signatures.json"
	}

	// Validate WAF configuration
	if cfg.WAF.ARN == "" {
		return nil, fmt.Errorf("WAF ARN is required")
	}
	if !strings.HasPrefix(cfg.WAF.ARN, "arn:aws:wafv2:") {
		return nil, fmt.Errorf("invalid WAF ARN format")
	}

	return &cfg, nil
}
