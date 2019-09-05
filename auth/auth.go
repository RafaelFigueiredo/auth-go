// Package auth is used to create a standalone server for authentication, or just use the library to validade requests.
//
// Features:
//
// * Token generated with this package is signed with RSA-512 to avoid sharing encryption key with clients.
//
// * Cookie saved with HttpOnly to avoid XSS atacks
//
// * Default handlers for login and logout
//
// * Default middleware for validade token via api or saved in a cookie
package auth

import (
	// stuff
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	// network and related
	"encoding/json"
	"net/http"

	"github.com/gorilla/sessions"

	// jwt
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"

	// database
	"database/sql"
	//it is just a driver
	_ "github.com/lib/pq"

	// encrypt
	"crypto/rsa"

	"golang.org/x/crypto/bcrypt"
)

// Define RSA key path
const (
	defaultPrivateKeyPath = "jwtRS256.key"
	defaultPublicKeyPath  = "jwtRS256.key.pub"
)

// Cookie store
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

// ServerConfig  is used to config the server
type ServerConfig struct {
	SignKeyPath   string          `json:"-"`
	VerifyKeyPath string          `json:"-"`
	RawSignKey    []byte          `json:"-"`
	RawVerifyKey  []byte          `json:"-"`
	Port          string          `json:"-"`
	LoginURL      string          `json:"login-url"`
	Database      *DatabaseConfig `json:"-"`
}

// DatabaseConfig store information to open connection to database
type DatabaseConfig struct {
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Database         string `json:"database"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	ConnectionString string `json:"connection_string"`
}

func (db DatabaseConfig) getConnectionString() string {
	//connectionString := fmt.Sprintf("%s:%s@tcp(%s)/%s", db.Username, db.Password, db.Host, db.Database)

	if db.ConnectionString == "" {
		connectionString := fmt.Sprintf("host=%s port=%d user=%s "+
			"password=%s dbname=%s sslmode=disable", db.Host, db.Port, db.Username, db.Password, db.Database)
		return connectionString
	}

	return db.ConnectionString
	//return "root:a1b2c3d4e5@tcp(127.0.0.1:3306)/jujuba"
}

// Server struct the handlers and middleware for authentication
type Server struct {
	SignKey   *rsa.PrivateKey `json:"-"`
	VerifyKey *rsa.PublicKey  `json:"-"`
	Port      string          `json:"-"`
	LoginURL  string          `json:"login-url"`
	Database  *DatabaseConfig `json:"-"`
}

// NewDefaultServer create a server with default config options
func NewDefaultServer() *Server {
	return NewServer(ServerConfig{})
}

// NewServer create a server with custom config options
func NewServer(config ServerConfig) *Server {
	if config.SignKeyPath == "" {
		config.SignKeyPath = defaultPrivateKeyPath
	}
	if config.VerifyKeyPath == "" {
		config.VerifyKeyPath = defaultPublicKeyPath
	}
	if config.Port == "" {
		config.Port = ":8000"
	}
	if config.LoginURL == "" {
		config.LoginURL = "login"
	}

	emptyDBConfig := &DatabaseConfig{}
	if config.Database == emptyDBConfig {
		config.Database = &DatabaseConfig{
			Host:     "127.0.0.1:3306",
			Database: "jujuba",
			Username: "root",
			Password: "a1b2c3d4e5",
		}
	}

	return &Server{
		SignKey:   LoadRSAPrivateKey(config.SignKeyPath),
		VerifyKey: LoadRSAPublicKey(config.VerifyKeyPath),
		Port:      config.Port,
		LoginURL:  config.LoginURL,
		Database:  config.Database,
	}
}

// LoadRSAPrivateKey is a helper function that load a RSA private key from a file
func LoadRSAPrivateKey(path string) *rsa.PrivateKey {
	var err error
	var signStream []byte
	var signKey *rsa.PrivateKey

	// Load and parse Private Key
	signStream, err = ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Error reading private key")
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signStream)
	if err != nil {
		log.Fatal(err)
	}

	return signKey
}

// LoadRSAPublicKey is a helper function that load a RSA public key from a file
func LoadRSAPublicKey(path string) *rsa.PublicKey {
	var err error
	var verifyStream []byte
	var verifyKey *rsa.PublicKey

	// Load and parse Public Key
	verifyStream, err = ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Error reading public key")
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyStream)

	if err != nil {
		log.Fatal(err)
	}

	return verifyKey
}

// Model definition

// User struct define our default model to read users from database
type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
	Auth *Auth  `json:"-"`
}

// Auth sruct define our (MODEL)
type Auth struct {
	Login     string `json:"login"`
	Password  string `json:"password"`
	SecretKey string `json:"secret"`
}

// Response define a default object to response, will be used with Ajax requests
type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Token   *Token `json:"token"`
}

// New is just a trigle to create a response only with the message
func (resp Response) New(message string) Response {
	resp.Status = "none"
	resp.Message = message
	resp.Token = &Token{}
	return resp
}

// Token store our JWT data
type Token struct {
	JWT string `json:"jwt"`
}

// Default login responses
var loginSuccessResponse = Response{
	Status:  "success",
	Message: "Logged with success.",
	Token:   &Token{}}

var loginErrorResponse = Response{
	Status:  "error",
	Message: "Login error. Please verify login and password",
	Token:   &Token{}}

// LoginHandler handler incomming authentication requests
func (s *Server) LoginHandler() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Decode request into Auth struct
		var authFromRequest Auth
		err := json.NewDecoder(r.Body).Decode(&authFromRequest)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Error in request")
			return
		}

		// Validate User Credentials
		// 1 - Connect to database
		// 2 - Prepare Statement
		// 3 - Query
		// 4 - Verify login and password

		// 	1/4 - Conectando ao banco de dados
		//  username:password@tcp(host)/database
		log.Println("Connecting to database...")

		db, err := sql.Open("postgres", s.Database.getConnectionString())
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		// 	2/4 - Prepate the statement
		// SELECT * FROM profiles INNER JOIN auth ON profiles.profile_id = auth.profile_id WHERE auth.login=?
		log.Println("Preparing statement...")

		stmt, err := db.Prepare("SELECT * FROM users INNER JOIN auth ON users.id = auth.user_id WHERE users.login=$1")

		if err != nil {
			log.Fatal(err)
		}
		defer stmt.Close()

		//	3/4 - Query
		log.Println("Quering...")

		//	Variable to be filled
		var (
			id        string
			name      string
			host      string
			password  string
			login     string
			secretKey string
		)

		log.Printf("%v", authFromRequest)

		//	Query just one row
		err = stmt.QueryRow(authFromRequest.Login).Scan(&id, &name, &host, &id, &login, &password, &secretKey)
		if err != nil {
			if err == sql.ErrNoRows {
				//	There were no rows, but otherwise no error occurred
				w.WriteHeader(http.StatusForbidden)
				fmt.Println("Error logging in")
				fmt.Fprint(w, "Invalid credentials")
				log.Println("USUÁRIO NÃO CADASTRADO")
				return
			}
			log.Printf("%v", err)
			return
		}

		auth := Auth{Login: login, Password: password, SecretKey: secretKey}
		user := User{ID: id, Name: name, Host: host, Auth: &auth}

		//	4/4 - Check password
		log.Println("Checking password...")

		if checkPasswordHash(authFromRequest.Password, user.Auth.Password) == true {

			tokenString, err := s.generateToken(user)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				JSONResponse(Response{Status: "error", Message: "Error signing token", Token: &Token{}}, w)
				log.Printf("Error signing token: %v\n", err)
				return
			}

			// Create a token instance using the token string and append it to a response
			response := Response{Status: "success", Message: "Authorized Login", Token: &Token{tokenString}}

			// Write a session cookie
			createCoockie("token", tokenString, w, r)

			// Send response
			JSONResponse(response, w)

			log.Println("Authorized Login")
		} else {

			w.WriteHeader(http.StatusForbidden)

			// Send response
			JSONResponse(Response{Status: "error", Message: "Invalid credentials", Token: &Token{}}, w)

			log.Printf("Invalid credentials")
		}
	}
}

// LogoutHandler handler request to logout
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get a session. Get() always returns a session, even if empty.
		session, err := store.Get(r, "jujuba")
		if err != nil {

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete cookie
		session.Options.MaxAge = -1

		// Save change in store
		err = session.Save(r, w)
		log.Printf("error saving session: %s", err)

		// Redirect to login page
		http.Redirect(w, r, s.LoginURL, http.StatusFound)

	}
}

// ValidateCookieMiddleware verify is a token in HttpOnly is valid
// BUG(rafaelfigueiredo) Verify if token come in http_only and if machine signature match
func (s *Server) ValidateCookieMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		////////////////////////////
		// Get a session. Get() always returns a session, even if empty.
		session, err := store.Get(r, "jujuba")
		if err != nil {

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Set some session values.
		tokenString := fmt.Sprintf("%s", session.Values["token"])

		// Validate token
		token, err := jwt.Parse(tokenString,
			func(token *jwt.Token) (interface{}, error) {
				return s.VerifyKey, nil
			})

		if err == nil {
			if token.Valid {
				h(w, r)
			} else {
				//w.WriteHeader(http.StatusUnauthorized)
				http.Redirect(w, r, s.LoginURL, http.StatusFound)
			}
		} else {
			//w.WriteHeader(http.StatusUnauthorized)
			http.Redirect(w, r, s.LoginURL, http.StatusFound)
		}

		////////////////////////////
		return
	}
}

// ValidateTokenMiddleware verify is a token appended to a request is valid
func (s *Server) ValidateTokenMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//validate token
		token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
			func(token *jwt.Token) (interface{}, error) {
				return s.VerifyKey, nil
			})

		log.Printf(token.Raw)
		if err == nil {

			if token.Valid {
				h(w, r)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				log.Printf("Token is not valid")
				JSONResponse(Response{Status: "error", Message: "Token is not valid", Token: &Token{}}, w)
			}
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Println("Unauthorised access to this resource")
			JSONResponse(Response{Status: "error", Message: "Unauthorised access to this resource", Token: &Token{}}, w)
		}

		return

	}
}

// Helper functions

// JSONResponse take a object, parse to JSON and write it as a response
func JSONResponse(response interface{}, w http.ResponseWriter) {

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
	log.Printf("BCrypt....password: %s , with hash: %s", password, hash)
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// generateToken create a JWT based on server config and user data.
func (s Server) generateToken(user User) (string, error) {
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
		claims["CustomUserInfo"] = struct {
			Name string
			Role string
		}{user.Name, "Member"}*/
	signer.Claims = claims

	tokenString, err := signer.SignedString(s.SignKey)

	return tokenString, err
}

func createCoockie(key string, value string, w http.ResponseWriter, r *http.Request) {
	// Get a session. Get() always returns a session, even if empty.
	session, err := store.Get(r, "jujuba")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Options.MaxAge = 3600

	// Set some session values.
	session.Values[key] = value
	// Save it before we write to the response/return from the handler.
	err = session.Save(r, w)

	if err != nil {
		log.Fatal("failed to save session", err)
	}
}
