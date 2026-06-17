package config

import (
	"encoding/json"
	"os"
)

type ProxyProvider struct {
	Type    int    `json:"type"`
	URL     string `json:"url"`
	Timeout int    `json:"timeout"`
}

type Config struct {
	MCBot                    string          `json:"MCBOT"`
	MinecraftDefaultProtocol int             `json:"MINECRAFT_DEFAULT_PROTOCOL"`
	ProxyProviders           []ProxyProvider `json:"proxy-providers"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
