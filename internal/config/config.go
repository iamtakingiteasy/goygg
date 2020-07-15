// Package config yaml
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

// Config yaml
type Config struct {
	Listen      string            `yaml:"listen"`
	External    string            `yaml:"external"`
	SkinDomains []string          `yaml:"skinDomains"`
	Meta        map[string]string `yaml:"meta"`
	Expiry      time.Duration     `yaml:"expiry"`
	TexturesDir string            `yaml:"texturesDir"`
	Database    struct {
		Host     string `yaml:"host"`
		Port     uint16 `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Dbname   string `yaml:"dbname"`
	} `yaml:"database"`
}

// NewConfig from file
func NewConfig(file string) (conf *Config, err error) {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = f.Close()
	}()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	conf = &Config{}

	if stat.Size() > 0 {
		err = yaml.NewDecoder(f).Decode(conf)
		if err != nil {
			return nil, err
		}
	}

	if conf.Meta == nil {
		conf.Meta = map[string]string{
			"implementationName":    "goygg",
			"implementationVersion": "1.0",
			"serverName":            "goygg",
		}
	}

	if conf.Listen == "" {
		conf.Listen = ":8080"
	}

	if conf.External == "" {
		conf.External = "https://minecraft.example.com"
	}

	if conf.SkinDomains == nil {
		conf.SkinDomains = []string{
			".example.com",
			".minecraft.example.com",
		}
	}

	if conf.Expiry == 0 {
		conf.Expiry = time.Hour
	}

	if conf.TexturesDir == "" {
		conf.TexturesDir = "./textures"
	}

	bs, err := yaml.Marshal(conf)
	if err != nil {
		return nil, err
	}

	ftmp, err := os.OpenFile(file+".tmp", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = ftmp.Close()
	}()

	_, err = ftmp.Write(bs)
	if err != nil {
		return nil, err
	}

	err = os.Rename(file+".tmp", file)
	if err != nil {
		return nil, err
	}

	return conf, nil
}
