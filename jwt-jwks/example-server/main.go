/*
Example Go server providing endpoints for JWT and JWKS testing.
*/
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// generate private key used to sign token and expose its public part in the jwks
var privKey = genRSAkey()

func main() {
	port := flag.String("port", "", "port to listen on (required)")
	flag.Parse()

	if *port == "" {
		log.Fatal("Error: -port flag is required")
	}

	addr := ":" + *port
	fmt.Printf("server start at %s\n", addr)

	m := mux.NewRouter()
	m.HandleFunc("/jwks", giveJWKSHandler)
	m.HandleFunc("/token", giveJWTHandler)
	if err := http.ListenAndServe(addr, m); err != nil { // listens to :<port>, call either /jwks or /token
		fmt.Printf("Server down: %v\n", err)
	}
}

func giveJWKSHandler(w http.ResponseWriter, r *http.Request) {

	// log request to server
	log.Printf("Request to get jwks from %v\n", r.RemoteAddr)

	// Create JWKS - needs to be an array of keys, here we only include one key
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			keyToJWK(privKey, "server1-key1"),
		},
	}

	// Serialize JWKS to JSON
	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		http.Error(w, "Failed to serialize JWKS to JSON", http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")

	// Write JWKS JSON to response
	_, err = w.Write(jwksJSON)
	if err != nil {
		log.Println("Failed to write JWKS JSON to response:", err)
	}
}

func giveJWTHandler(w http.ResponseWriter, r *http.Request) {

	log.Printf("Request to get jwt from %v\n", r.RemoteAddr)

	// Get the token instance with the Signing method
	token := jwt.New(jwt.GetSigningMethod("RS256"))

	// Set wanted claims to token
	token.Claims = &jwt.MapClaims{
		"iss": "example-issuer",
		"sub": uuid.New().String(),                     // subject claim with UUID
		"iat": time.Now().Unix(),                       // token issued at current time
		"exp": time.Now().Add(10 * time.Minute).Unix(), // token expires in 10 minutes
	}

	// kid needs to be in token header for keyfunc lib to accept token
	token.Header["kid"] = "server1-key1"

	// Sign the token with your secret key
	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		panic(err)
	}

	// print token to caller
	fmt.Fprint(w, tokenStr)
}

// takes a rsa private key and returns a jwk of the public part
func keyToJWK(key *rsa.PrivateKey, kid string) map[string]any {
	// Create JWK
	jwk := map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		"kid": kid,
	}
	return jwk
}

// returns a private key with rsa algorithm
func genRSAkey() *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return privateKey
}
