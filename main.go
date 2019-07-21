package main

import (
	"log"
	"net/http"

	"github.com/rafaelfigueiredo/auth-go/auth"
	// Midlewares
)

// MAIN
func main() {
	var JWTServer = auth.NewDefaultServer()

	//PUBLIC ENDPOINTS
	http.HandleFunc("/login", JWTServer.LoginHandler())

	//PROTECTED ENDPOINTS
	http.HandleFunc("/resource", JWTServer.ValidateTokenMiddleware(ProtectedHandler))

	log.Printf("Now listening at %v", JWTServer.Port)
	http.ListenAndServe(JWTServer.Port, nil)
}

// ProtectedHandler is used to test access with JWT
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {

	response := auth.Response{}.New("Gained access to protected resource")
	auth.JSONResponse(response, w)
}
