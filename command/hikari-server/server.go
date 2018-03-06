package main

import (
	"hikari-go/hikariserver"
	"runtime"
)

func main() {
	hikariserver.Start()
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
