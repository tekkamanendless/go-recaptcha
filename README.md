# go-recaptcha
[![Build Status](https://travis-ci.org/tekkamanendless/go-recaptcha.png)](https://travis-ci.org/tekkamanendless/go-recaptcha)
[![Go Report Card](https://goreportcard.com/badge/github.com/tekkamanendless/go-recaptcha)](https://goreportcard.com/report/github.com/tekkamanendless/go-recaptcha)
[![GoDoc](https://godoc.org/github.com/tekkamanendless/go-recaptcha?status.svg)](https://godoc.org/github.com/tekkamanendless/go-recaptcha)

## About
This package handles [reCAPTCHA](https://www.google.com/recaptcha) (API versions [2](https://developers.google.com/recaptcha/intro) and [3](https://developers.google.com/recaptcha/docs/v3)) form submissions in [Go](http://golang.org/).

## Usage
Import the package:

```
import "github.com/tekkamanendless/go-recaptcha"
```

Create a new reCAPTCHA verifier.

```
recaptchaVerifier := recaptcha.New("YOUR_PRIVATE_KEY")
```

Verify a token.

```
success, err := recaptchaVerifier.Verify("SOME_RECAPTCHA_RESPONSE_TOKEN")
```

Or verify with a client IP address, too:

```
success, err := recaptchaVerifier.VerifyRemoteIP(clientIpAddress, "SOME_RECAPTCHA_RESPONSE_TOKEN")
```

This workflow supports both [reCAPTCHA v2](https://developers.google.com/recaptcha/intro) and [reCAPTCHA v3](https://developers.google.com/recaptcha/docs/v3).

## Testing
You may use the included `recaptchatest` package to create a reCAPTCHA server suitable for unit testing.

```
import "github.com/tekkamanendless/go-recaptcha/recaptchatest"
```

```
// Create a new reCAPTCHA test server.
testServer := recaptchatest.NewServer()
defer testServer.Close()

// Create a new site.
site := testServer.NewSite()

// Create your reCAPTCHA verifier normally.
r := recaptcha.New(site.PrivateKey)

// Override the endpoint.
r.VerifyEndpoint = testServer.VerifyEndpoint()

// Generate a response token from the site.
token := site.NewResponseToken()

// Verify the token normally.
success, err := r.Verify(token)
```
