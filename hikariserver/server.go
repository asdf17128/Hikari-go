package hikariserver

func Start() {
	loadConfig()
	startHikariServer()
}
