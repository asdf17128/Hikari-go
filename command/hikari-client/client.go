package main

import (
	"hikari-go/hikariclient"
	"runtime"
)

func main() {
	hikariclient.Start()
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
