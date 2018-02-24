package hikariclient

func Start() {
	loadConfig()
	initHandle()
	startSocksServer()
}
