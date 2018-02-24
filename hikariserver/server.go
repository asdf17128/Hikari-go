package hikariserver

func Start() {
	loadConfig()
	initHandle()
	startHikariServer()
}
