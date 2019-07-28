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
	http.HandleFunc("/api/login", JWTServer.LoginHandler())

	//PROTECTED ENDPOINTS
	//API with JWT attached to request
	http.HandleFunc("/api/resource", JWTServer.ValidateTokenMiddleware(ProtectedHandlerAPI))

	//View with JWT attached to a cookie
	http.HandleFunc("/admin", JWTServer.ValidateCookieMiddleware(ProtectedHandlerView))

	log.Printf("Now listening at %v", JWTServer.Port)
	http.ListenAndServe(JWTServer.Port, nil)
}

// ProtectedHandlerAPI is used to test access with JWT
func ProtectedHandlerAPI(w http.ResponseWriter, r *http.Request) {

	response := auth.Response{}.New("Gained access to protected resource")
	auth.JSONResponse(response, w)
}

// ProtectedHandlerView is used to test access with cookie sessioin
func ProtectedHandlerView(w http.ResponseWriter, r *http.Request) {

	w.Write([]byte("Hello World"))
}
