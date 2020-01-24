package recaptchatest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	t.Run("Server has a URL", func(t *testing.T) {
		testServer := NewServer()
		defer testServer.Close()

		assert.NotEqual(t, "", testServer.VerifyEndpoint())
	})
}

func TestSite(t *testing.T) {
	t.Run("Site has keys", func(t *testing.T) {
		testServer := NewServer()
		defer testServer.Close()

		site := testServer.NewSite()
		assert.NotEqual(t, "", site.PublicKey)
		assert.NotEqual(t, "", site.PrivateKey)
	})
	t.Run("Generate a token", func(t *testing.T) {
		testServer := NewServer()
		defer testServer.Close()

		site := testServer.NewSite()

		token := site.NewResponseToken()
		assert.NotEqual(t, "", token)
	})
}
