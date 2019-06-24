package auth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	//ReadFile
	"io/ioutil"
	//Log
	"log"

	"net/http"

	// Midlewares
	"github.com/codegangsta/negroni"

	//JWt
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"

	//database
	"database/sql"

	//this is just a drive
	_ "github.com/go-sql-driver/mysql"

	//encrypt
	"golang.org/x/crypto/bcrypt"
)

// Define RSA key path
const (
	privKeyPath = "jwtRS256.key"
	pubKeyPath  = "jwtRS256.key.pub"
)

/////////////////////////////////////////////////////////////////////////
///////////////////// APP DEFINITION ////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

// App is our application object
type App struct {
	VerifyKey *rsa.PublicKey  `json:"-"`
	SignKey   *rsa.PrivateKey `json:"-"`
	Port      string          `json:"-"`
}

// Init load configuration and key files
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

// Run start the server
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

/////////////////////////////////////////////////////////////////////////
////////////////////// USER DEFINITION //////////////////////////////////
/////////////////////////////////////////////////////////////////////////

// User Struct (MODEL)
type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
	Auth *Auth  `json:"auth"`
}

// Auth Struct (MODEL)
type Auth struct {
	Login     string `json:"login"`
	Password  string `json:"password"`
	SecretKey string `json:"secretkey"`
}

/////////////////////////////////////////////////////////////////////////
////////////////// TOKEN AND RESPONSE DEFINITION/////////////////////////
/////////////////////////////////////////////////////////////////////////
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Token   *Token `json:"token"`
}

type Token struct {
	Token string `json:"token"`
}

func (resp Response) New(message string) Response {
	resp.Status = "none"
	resp.Message = message
	resp.Token = &Token{}
	return resp
}

/////////////////////////////////////////////////////////////////////////
///////////////// LOGIN HANDLER AND CHECKJWT MIDLEWARE //////////////////
/////////////////////////////////////////////////////////////////////////

//@todo this shit is just to test, DELETE!!
func (app App) ProtectedHandler(w http.ResponseWriter, r *http.Request) {

	response := Response{}.New("Gained access to protected resource")
	jsonResponse(response, w)
}

// LoginHandler handle a standard authentication
func (app App) LoginHandler(w http.ResponseWriter, r *http.Request) {

	var authFromRequest Auth

	//decode request into UserCredentials struct
	err := json.NewDecoder(r.Body).Decode(&authFromRequest)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Error in request")
		return
	}

	//@delete this - secuty issue
	fmt.Println(authFromRequest.Login, authFromRequest.Password)

	/////////////////////////////////////////////////////////////////
	////////////////////// validate user credentials/////////////////
	/////////////////////////////////////////////////////////////////

	/* 1/5 - Conectando ao banco de dados
	 * username:password@tcp(host)/database **/
	log.Println("Connecting to database...")

	db, err := sql.Open("mysql", "root:a1b2c3d4e5@tcp(127.0.0.1:3306)/jujuba")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 2/5 - Prepate the statement
	log.Println("Preparing statement...")
	stmt, err := db.Prepare("SELECT * FROM profiles INNER JOIN auth ON profiles.profile_id = auth.profile_id WHERE auth.login=?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	// 3/5 - Query
	// Variable to be filled
	var user User
	var auth Auth
	var (
		id        string
		name      string
		host      string
		password  string
		login     string
		secretKey string
	)

	log.Println("Quering...")
	err = stmt.QueryRow(authFromRequest.Login).Scan(&id, &name, &host, &id, &login, &password, &secretKey)
	if err != nil {
		if err == sql.ErrNoRows {
			// there were no rows, but otherwise no error occurred
			w.WriteHeader(http.StatusForbidden)
			fmt.Println("Error logging in")
			fmt.Fprint(w, "Invalid credentials")

			log.Println("USUÁRIO NÃO CADASTRADO")
			return
		} else {
			log.Printf("%v", err)
		}
	}

	auth = Auth{Login: login, Password: password, SecretKey: secretKey}
	user = User{ID: id, Name: name, Host: host, Auth: &auth}

	log.Printf("%v", user)

	// 5/5 - Check password
	log.Println("Checking password...")
	if checkPasswordHash(authFromRequest.Password, user.Auth.Password) == true {

		tokenString, err := app.generateToken(user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Error while signing the token")
			log.Printf("Error signing token: %v\n", err)
			return
		}
		//create a token instance using the token string
		response := Response{Status: "success", Message: "Authorized Login", Token: &Token{tokenString}}
		jsonResponse(response, w)
		log.Println("SUCCESS")
	} else {

		w.WriteHeader(http.StatusForbidden)
		fmt.Println("Error logging in")
		fmt.Fprint(w, "Invalid credentials")
		log.Println("ERROR")
	}

	log.Printf("Login credentials: %v", authFromRequest)
}

// ValidateTokenMiddleware check if the token signature is valid
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

//--------------------------------------HELPER FUNCTIONS --------------------------------------------//

// jsonResponse take a object, parse to JSON and write it as a response
func jsonResponse(response interface{}, w http.ResponseWriter) {

	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

// hashPassword create a hash of the plain password @todo: change bcrypt to argon2
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// checkPasswordHash compare a plain passwort to a hash and return true if match
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (app App) generateToken(user User) (string, error) {
	//create a rsa 256 signer
	signer := jwt.New(jwt.GetSigningMethod("RS256"))

	//set claims
	claims := make(jwt.MapClaims)
	claims["sub"] = user.ID
	claims["iss"] = "rafaelfigueiredo.github.io"
	claims["exp"] = time.Now().Add(time.Minute * 20).Unix()
	claims["iat"] = time.Now().Unix()
	claims["aud"] = user.Host
	/*
		claims["iss"] = "admin"
		claims["exp"] = time.Now().Add(time.Minute * 20).Unix()

			claims["CustomUserInfo"] = struct {
				Name string
				Role string
			}{user.Name, "Member"}*/
	signer.Claims = claims

	tokenString, err := signer.SignedString(app.SignKey)

	return tokenString, err
}
