package recaptcha_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tekkamanendless/go-recaptcha"
	"github.com/tekkamanendless/go-recaptcha/recaptchatest"
)

func TestNewRecaptcha(t *testing.T) {
	t.Run("New returns a ready instance", func(t *testing.T) {
		privateKey := "my-key"
		r := recaptcha.New(privateKey)
		require.NotNil(t, r)
		require.Equal(t, privateKey, r.PrivateKey)
		require.Equal(t, "", r.VerifyEndpoint)
	})
}

func TestVerifyRecaptcha(t *testing.T) {
	t.Run("Bogus site", func(t *testing.T) {
		r := recaptcha.New("my-private-key")
		require.NotNil(t, r)
		r.VerifyEndpoint = "0.0.0.1/bogus/path"

		success, err := r.Verify("some-token")
		require.NotNil(t, err)
		require.False(t, success)
	})
	t.Run("Token verification", func(t *testing.T) {
		testServer := recaptchatest.NewServer()
		defer testServer.Close()
		site := testServer.NewSite()

		r := recaptcha.New(site.PrivateKey)
		require.NotNil(t, r)
		r.VerifyEndpoint = testServer.VerifyEndpoint()

		token := site.NewResponseToken()
		require.NotEqual(t, "", token)

		success, err := r.Verify(token)
		require.Nil(t, err)
		require.True(t, success)

		// You can't verify the same token twice.
		success, err = r.Verify(token)
		require.Nil(t, err)
		require.False(t, success)
	})
	t.Run("Token verification with remote IP", func(t *testing.T) {
		testServer := recaptchatest.NewServer()
		defer testServer.Close()
		site := testServer.NewSite()

		r := recaptcha.New(site.PrivateKey)
		require.NotNil(t, r)
		r.VerifyEndpoint = testServer.VerifyEndpoint()

		token := site.NewResponseTokenRemoteIP("1.2.3.4")
		require.NotEqual(t, "", token)

		success, err := r.VerifyRemoteIP("1.2.3.4", token)
		require.Nil(t, err)
		require.True(t, success)

		// You can't verify the same token twice.
		success, err = r.VerifyRemoteIP("1.2.3.4", token)
		require.Nil(t, err)
		require.False(t, success)
	})
	t.Run("Token verification with incorrect remote IP", func(t *testing.T) {
		testServer := recaptchatest.NewServer()
		defer testServer.Close()
		site := testServer.NewSite()

		r := recaptcha.New(site.PrivateKey)
		require.NotNil(t, r)
		r.VerifyEndpoint = testServer.VerifyEndpoint()

		token := site.NewResponseTokenRemoteIP("1.2.3.4")
		require.NotEqual(t, "", token)

		success, err := r.VerifyRemoteIP("9.9.9.9", token)
		require.Nil(t, err)
		require.False(t, success)
	})
}
