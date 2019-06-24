package main

import (
	"./auth"
	"log"
	"net/http"
		// Midlewares
		"github.com/codegangsta/negroni"
)

// MAIN
func main() {
	var JWTServer auth.App
	JWTServer.Init()
	Run(JWTServer)
}

// Run start the server
func Run(app auth.App) {

	//PUBLIC ENDPOINTS
	http.HandleFunc("/login", app.LoginHandler)

	//PROTECTED ENDPOINTS
	http.Handle("/resource/", negroni.New(
		negroni.HandlerFunc(app.ValidateTokenMiddleware),
		negroni.Wrap(http.HandlerFunc(ProtectedHandler)),
	))

	log.Printf("Now listening at %v", app.Port)
	http.ListenAndServe(app.Port, nil)
}



// ProtectedHandler is used to test access with JWT
func ProtectedHandler(w http.ResponseWriter, r *http.Request) {

	response := auth.Response{}.New("Gained access to protected resource")
	auth.JSONResponse(response, w)
}