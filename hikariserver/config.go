package hikariserver

import (
	"hikari-go/hikaricommon"
	"os"
	"path"
)

type config struct {
	ListenAddress  string   `json:"listenAddress"`
	ListenPort     uint16   `json:"listenPort"`
	PrivateKeyList []string `json:"privateKeyList"`
	Secret         string   `json:"secret"`
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
		configFilePath = path.Join(cd, "../server.json")
	}

	cfg = &config{}
	hikaricommon.LoadConfig(configFilePath, cfg)
}
