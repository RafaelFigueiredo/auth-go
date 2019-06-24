package main

import (
	"./auth"
)

// MAIN
func main() {
	var JWTServer auth.App
	JWTServer.Init()
	JWTServer.Run()
}
