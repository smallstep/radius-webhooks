package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"time"

	"go.step.sm/crypto/x509util"
)

var certFile = "webhook.crt"
var keyFile = "webhook.key"
var address = ":8080"

// For demonstration only. Do not hardcode or commit actual webhook secrets.
var webhookIDsToSecrets = map[string]secret{
	"c346e7c0-6703-4590-8a04-ef86bbd4c7a4": secret{
		Key: "J2ykRJsvI5Jnll/IUGgyYYBoNhlbMnO5fidWKEmEwovMywVHI+E2eVoT1/uDMyP544IWiNwdGvT4ruMqdCHODA==",
	},
}

var allowCNs = []string{
	"josh@smallstep.com",
}

type secret struct {
	Key      string
	Bearer   string
	Username string
	Password string
}

type handler struct {
	Allow   func(certificate *x509Certificate) (bool, error)
	Secrets map[string]secret
}

type requestBody struct {
	Timestamp       time.Time        `json:"timestamp"`
	ClientIP        string           `json:"clientIP,omitempty"`
	X509Certificate *x509Certificate `json:"x509Certificate,omitempty"`
}

type authorizeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *authorizeError) Error() string {
	return fmt.Sprintf("%s (%s)", e.Message, e.Code)
}

type responseBody struct {
	Allow bool            `json:"allow"`
	Error *authorizeError `json:"error,omitempty"`
}

type x509Certificate struct {
	*x509util.Certificate
	PublicKey          []byte    `json:"publicKey"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	Raw                []byte    `json:"raw"`
}

func (h *handler) authenticate(w http.ResponseWriter, r *http.Request) (*requestBody, bool) {
	id := r.Header.Get("X-Smallstep-Webhook-ID")
	if id == "" {
		http.Error(w, "Missing X-Smallstep-Webhook-ID header", http.StatusBadRequest)
		return nil, false
	}
	secret, ok := h.Secrets[id]
	if !ok {
		log.Printf("Missing signing secret for webhook %s", id)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}
	if secret.Bearer != "" {
		wantAuth := fmt.Sprintf("Bearer %s", secret.Bearer)
		if r.Header.Get("Authorization") != wantAuth {
			log.Printf("Incorrect bearer authorization header for %s", id)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
	} else if secret.Username != "" || secret.Password != "" {
		user, pass, _ := r.BasicAuth()
		if user != secret.Username || pass != secret.Password {
			log.Printf("Incorrect basic authorization header for %s", id)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil, false
		}
	}

	sig, err := hex.DecodeString(r.Header.Get("X-Smallstep-Signature"))
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Invalid X-Smallstep-Signature header", http.StatusBadRequest)
		return nil, false
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return nil, false
	}

	hmacKey, err := base64.StdEncoding.DecodeString(secret.Key)
	if err != nil {
		log.Printf("Failed to decode signing secret for %s: %v", id, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}

	hm := hmac.New(sha256.New, hmacKey)
	hm.Write(body)
	mac := hm.Sum(nil)
	if ok := hmac.Equal(sig, mac); !ok {
		log.Printf("Failed to verify request signature for %s", id)
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return nil, false
	}

	wrb := &requestBody{}
	err = json.Unmarshal(body, wrb)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}

	return wrb, true
}

func (h *handler) Authorize(w http.ResponseWriter, r *http.Request) {
	wrb, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	allow, err := h.Allow(wrb.X509Certificate)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	err = json.NewEncoder(w).Encode(responseBody{Allow: allow})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "Internal Server Error", 500)
		return
	}

	fmt.Printf("Received authorizing webhook request. Sent allow: %t\n", allow)
}

func main() {
	s := http.Server{
		Addr: address,
	}

	h := &handler{
		Secrets: webhookIDsToSecrets,
		Allow: func(cert *x509Certificate) (bool, error) {
			return slices.Contains(allowCNs, cert.Subject.CommonName), nil
		},
	}
	http.HandleFunc("/authorize", h.Authorize)

	fmt.Printf("Listening on %s\n", s.Addr)
	err := s.ListenAndServeTLS(certFile, keyFile)
	log.Fatal(err)
}
