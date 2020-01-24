// Package recaptcha handles reCAPTCHA (http://www.google.com/recaptcha) form submissions
//
// This package is designed to be called from within an HTTP server or web framework
// which offers reCAPTCHA form inputs and requires them to be evaluated for correctness
package recaptcha

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Recaptcha contains the configuration and functions necessary to perform reCAPTCHA validations.
type Recaptcha struct {
	VerifyEndpoint string      // This is the endpoint; if empty, it will default to the production endpoint.
	PrivateKey     string      // This is your site's private key.
	httpClient     http.Client // This is the http client to use.
}

// RecaptchaResponse is the response that we get back from the "siteverify" endpoint.
type RecaptchaResponse struct {
	Success     bool      `json:"success"`      // Whether this request was a valid reCAPTCHA token for your site.
	Score       float64   `json:"score"`        // (v3 only) The score for this request (0.0 - 1.0).
	Action      string    `json:"action"`       // (v3 only) The action name for this request (important to verify).
	ChallengeTS time.Time `json:"challenge_ts"` // Timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ).
	Hostname    string    `json:"hostname"`     // The hostname of the site where the reCAPTCHA was solved.
	ErrorCodes  []string  `json:"error-codes"`  // (Optional)
}

// DefaultVerifyEndpoint is the default production endpoint for verifying a token.
const DefaultVerifyEndpoint = "https://www.google.com/recaptcha/api/siteverify"

// New creates a new Recaptcha instance that can verify reCAPTCHA tokens.
func New(privateKey string) *Recaptcha {
	r := new(Recaptcha)
	r.PrivateKey = privateKey

	return r
}

// check the response token (and optinoally the remote IP address).
//
// If the error is nil, then this will always return a RecaptchaResponse.
func (r *Recaptcha) check(remoteIP, response string) (*RecaptchaResponse, error) {
	// This is the endpoint that we're going to use.
	verifyEndpoint := r.VerifyEndpoint
	// If none was specified, then use the default.
	if verifyEndpoint == "" {
		verifyEndpoint = DefaultVerifyEndpoint
	}

	postParameters := url.Values{}
	postParameters.Set("secret", r.PrivateKey)
	postParameters.Set("response", response)
	if remoteIP != "" {
		postParameters.Set("remoteip", remoteIP)
	}

	httpRequest, err := http.NewRequest("POST", verifyEndpoint, strings.NewReader(postParameters.Encode()))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpResponse, err := r.httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()

	contents, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	recaptchaResponse := new(RecaptchaResponse)
	err = json.Unmarshal(contents, recaptchaResponse)
	if err != nil {
		return nil, err
	}
	return recaptchaResponse, nil
}

// Verify a response token.
func (r *Recaptcha) Verify(response string) (bool, error) {
	remoteIP := ""
	recaptchaResponse, err := r.check(remoteIP, response)
	if err != nil {
		return false, err
	}
	return recaptchaResponse.Success, nil
}

// VerifyRemoteIP verify a response token along with the IP address.
func (r *Recaptcha) VerifyRemoteIP(remoteIP, response string) (bool, error) {
	recaptchaResponse, err := r.check(remoteIP, response)
	if err != nil {
		return false, err
	}
	return recaptchaResponse.Success, nil
}
