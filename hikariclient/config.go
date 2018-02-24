package hikariclient

import (
	"hikari-go/hikaricommon"
	"os"
	"path"
)

type config struct {
	ListenAddress string `json:"listenAddress"`
	ListenPort    uint16 `json:"listenPort"`
	ServerAddress string `json:"serverAddress"`
	ServerPort    uint16 `json:"serverPort"`
	PrivateKey    string `json:"privateKey"`
	Secret        string `json:"secret"`
}

var cfg *config

func loadConfig() {
	var configFilePath string

	// read config from args
	args := os.Args
	if len(args) >= 2 {
		configFilePath = args[1]
	} else {
		cd := args[0]
		configFilePath = path.Join(cd, "../client.json")
	}

	cfg = &config{}
	hikaricommon.LoadConfig(configFilePath, cfg)
}
