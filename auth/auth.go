package auth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"

	//ReadFile
	"io/ioutil"
	//Log
	"log"

	"net/http"
	"strings"
	"time"

	// Midlewares
	"github.com/codegangsta/negroni"
	//JWt
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

// Define RSA key path
const (
	privKeyPath = "jwtRS256.key"
	pubKeyPath  = "jwtRS256.key.pub"
)

type App struct {
	VerifyKey *rsa.PublicKey  `json:"-"`
	SignKey   *rsa.PrivateKey `json:"-"`
	Port      string          `json:"-"`
}

func (app *App) Init() {
	app.Port = ":8000"
	// ----------------------------- RSA KEY LOAD --------------------------//
	// Varia
	var err error
	var signKey, verifyKey []byte
	// Load and parse Private Key
	signKey, err = ioutil.ReadFile(privKeyPath)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	app.SignKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKey)
	if err != nil {
		log.Printf("error parsing RSA private key: %v\n", err)
	}

	// Load and parse Public Key
	verifyKey, err = ioutil.ReadFile(pubKeyPath)
	if err != nil {
		log.Fatal("Error reading public key")
		return
	}
	app.VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyKey)

	if err != nil {
		log.Printf("error parsing RSA private key: %v\n", err)
	}
}

// DEFINE ENTRY POINTS
func (app App) Run() {

	//PUBLIC ENDPOINTS
	http.HandleFunc("/login", app.LoginHandler)

	//PROTECTED ENDPOINTS
	http.Handle("/resource/", negroni.New(
		negroni.HandlerFunc(app.ValidateTokenMiddleware),
		negroni.Wrap(http.HandlerFunc(app.ProtectedHandler)),
	))

	log.Printf("Now listening at %v", app.Port)
	http.ListenAndServe(app.Port, nil)
}

//STRUCT DEFINITIONS

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Data string `json:"data"`
}

type Token struct {
	Token string `json:"token"`
}

//////////////////////////////////////////

/////////////ENDPOINT HANDLERS////////////

/////////////////////////////////////////

func (app App) ProtectedHandler(w http.ResponseWriter, r *http.Request) {

	response := Response{"Gained access to protected resource"}
	JsonResponse(response, w)
}

func (app App) LoginHandler(w http.ResponseWriter, r *http.Request) {

	var user UserCredentials

	//decode request into UserCredentials struct
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Error in request")
		return
	}

	fmt.Println(user.Username, user.Password)

	//validate user credentials
	if strings.ToLower(user.Username) != "alexcons" {
		if user.Password != "kappa123" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Println("Error logging in")
			fmt.Fprint(w, "Invalid credentials")
			return
		}
	}

	//create a rsa 256 signer
	signer := jwt.New(jwt.GetSigningMethod("RS256"))

	//set claims
	claims := make(jwt.MapClaims)
	claims["iss"] = "admin"
	claims["exp"] = time.Now().Add(time.Minute * 20).Unix()
	claims["CustomUserInfo"] = struct {
		Name string
		Role string
	}{user.Username, "Member"}
	signer.Claims = claims

	tokenString, err := signer.SignedString(app.SignKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while signing the token")
		log.Printf("Error signing token: %v\n", err)
	}

	//create a token instance using the token string
	response := Token{tokenString}
	JsonResponse(response, w)
}

//AUTH TOKEN VALIDATION

func (app App) ValidateTokenMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	//validate token
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return app.VerifyKey, nil
		})

	log.Printf(token.Raw)
	if err == nil {

		if token.Valid {
			next(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Token is not valid")
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Unauthorised access to this resource")
	}
}

//HELPER FUNCTIONS

func JsonResponse(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}
