package recaptchatest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/google/uuid"
	"github.com/tekkamanendless/go-recaptcha"
)

// Server is a test server that can act as a reCAPTCHA stand-in for unit tests.
type Server struct {
	verifyEndpoint string           // This is the verify endpoint.
	server         *httptest.Server // This is the HTTP test server.
	sites          []*Site          // This is the list of reCAPTCHA sites and their associated states.
}

// Site represents a reCAPTCHA site.
type Site struct {
	PublicKey  string                // This is the public key.
	PrivateKey string                // This is the private key.
	tokens     map[string]*TokenData // This is the set of tokens.
}

// TokenData represents the data for a token.
type TokenData struct {
	Used           bool      // Whether or not this token has been used already.
	RemoteIP       string    // (optional) The remote IP address.
	ExpirationDate time.Time // This is when the token expires.
}

// NewServer creates a new test server.
func NewServer() *Server {
	s := new(Server)

	myHandler := http.NewServeMux()
	myHandler.HandleFunc("/recaptcha/api/siteverify", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		statusCode, recaptchaResponse := func() (int, *recaptcha.RecaptchaResponse) {
			recaptchaResponse := new(recaptcha.RecaptchaResponse)
			recaptchaResponse.Success = false
			recaptchaResponse.ChallengeTS = time.Now()

			err := r.ParseForm()
			if err != nil {
				recaptchaResponse.ErrorCodes = append(recaptchaResponse.ErrorCodes, "bad-request")
				return http.StatusOK, recaptchaResponse
			}

			privateKey := r.FormValue("secret")
			token := r.FormValue("response")
			remoteIP := r.FormValue("remoteip")

			if privateKey == "" {
				recaptchaResponse.ErrorCodes = append(recaptchaResponse.ErrorCodes, "missing-input-secret")
				return http.StatusOK, recaptchaResponse
			}

			site := s.getSiteByPrivateKey(privateKey)
			if site == nil {
				// This is an invalid private key; it does not correspond to any site.
				recaptchaResponse.ErrorCodes = append(recaptchaResponse.ErrorCodes, "invalid-input-secret")
				return http.StatusOK, recaptchaResponse
			}

			if token == "" {
				recaptchaResponse.ErrorCodes = append(recaptchaResponse.ErrorCodes, "missing-input-response")
				return http.StatusOK, recaptchaResponse
			}

			tokenData, present := site.tokens[token]
			if !present {
				// This is an invalid token; we never generated it.
				recaptchaResponse.ErrorCodes = append(recaptchaResponse.ErrorCodes, "invalid-input-response")
				return http.StatusOK, recaptchaResponse
			}

			if tokenData.Used {
				recaptchaResponse.ErrorCodes = append(recaptchaResponse.ErrorCodes, "timeout-or-duplicate")
				return http.StatusOK, recaptchaResponse
			}

			tokenData.Used = true

			if remoteIP != "" && tokenData.RemoteIP != remoteIP {
				return http.StatusOK, recaptchaResponse
			}

			recaptchaResponse.Success = true
			return http.StatusOK, recaptchaResponse
		}()

		payload, err := json.Marshal(recaptchaResponse)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(statusCode)
		w.Write(payload)
	})

	s.server = httptest.NewServer(myHandler)

	return s
}

// Close the server.
func (s *Server) Close() {
	s.server.Close()
}

// VerifyEndpoint returns the URL to use for verifying a token.
func (s *Server) VerifyEndpoint() string {
	return s.server.URL + "/recaptcha/api/siteverify"
}

// NewSite creates a new reCAPTCHA site.
func (s *Server) NewSite() *Site {
	site := new(Site)

	newUUID, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	site.PublicKey = newUUID.String()

	newUUID, err = uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	site.PrivateKey = newUUID.String()

	s.sites = append(s.sites, site)

	return site
}

// getServerKeyByPublicKey returns the site with the given public key.
func (s *Server) getSiteByPublicKey(publicKey string) *Site {
	for _, site := range s.sites {
		if site.PublicKey == publicKey {
			return site
		}
	}
	return nil
}

// getSiteByPrivateKey returns the site with the given private key.
func (s *Server) getSiteByPrivateKey(privateKey string) *Site {
	for _, site := range s.sites {
		if site.PrivateKey == privateKey {
			return site
		}
	}
	return nil
}

// NewResponseToken simulates generating a valid response token.
func (s *Site) NewResponseToken() string {
	tokenData := &TokenData{
		ExpirationDate: time.Now().Add(2 * time.Minute),
	}
	token := s.GenerateToken(tokenData)
	return token
}

// NewResponseTokenRemoteIP simulates generating a valid response token for the given remote IP address.
func (s *Site) NewResponseTokenRemoteIP(remoteIP string) string {
	tokenData := &TokenData{
		ExpirationDate: time.Now().Add(2 * time.Minute),
		RemoteIP:       remoteIP,
	}
	token := s.GenerateToken(tokenData)
	return token
}

// GenerateToken generates a new token for the given token data.
func (s *Site) GenerateToken(tokenData *TokenData) string {
	var token string

	newUUID, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	token = newUUID.String()

	if s.tokens == nil {
		s.tokens = map[string]*TokenData{}
	}
	s.tokens[token] = tokenData

	return token
}
