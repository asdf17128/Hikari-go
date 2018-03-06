package hikariclient

import (
	"log"
	"net"
	"strconv"
)

func startSocksServer() {
	initHandle()

	ads := cfg.ListenAddress
	port := strconv.Itoa(int(cfg.ListenPort))
	listenAddress := net.JoinHostPort(ads, port)

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("listen on address '%v' err, %v\n", listenAddress, err)
	}
	defer listener.Close()

	// start
	log.Printf("socks server start on '%v'\n", listenAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept err, %v\n", err)
			break
		}

		go handleConnection(&conn)
	}

	log.Println("socks server stop")
}
