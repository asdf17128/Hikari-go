package hikariserver

import (
	"log"
	"net"
	"strconv"
)

func startHikariServer() {
	// init status
	initStatus()

	// init listener
	ads := cfg.ListenAddress
	port := strconv.Itoa(int(cfg.ListenPort))
	listenAddress := net.JoinHostPort(ads, port)

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("listen on address '%v' err, %v\n", listenAddress, err)
	}
	defer listener.Close()

	// accept
	log.Printf("hikari server start on '%v'\n", listenAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept err, %v\n", err)
			continue
		}

		go handleConnection(&conn)
	}

	log.Println("hikari server stop")
}
