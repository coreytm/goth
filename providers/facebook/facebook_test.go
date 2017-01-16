package facebook_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/facebook"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := facebookProvider(false)
	a.Equal(provider.ClientKey, os.Getenv("FACEBOOK_KEY"))
	a.Equal(provider.Secret, os.Getenv("FACEBOOK_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
	a.Equal(provider.SignRequests, false)
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), facebookProvider(false))
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := facebookProvider(false)
	session, err := provider.BeginAuth("test_state")
	s := session.(*facebook.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "facebook.com/dialog/oauth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("FACEBOOK_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=email")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := facebookProvider(false)

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://facebook.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*facebook.Session)
	a.Equal(session.AuthURL, "http://facebook.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func Test_GetProof(t *testing.T) {
	p := facebook.New("a3729797-3c02-43f6-af92-e00808cbd77c", "973f67f1-2794-401e-977b-184bd49d0174", "/foo", false, "email")
	s := facebook.Session{
		AccessToken: "a3729797-3c02-43f6-af92-e00808cbd77c",
	}

	proof, _ := p.GetProof(&s)

	assert.Equal(t, "\\j\x9b(2oXN9s6\xc1\x9a\x04R2L\x91\xd5n\xdd\xfd\x98\xc5R\x98ݚo\x02\n\xcb", string(proof))
}

func facebookProvider(signReq bool) *facebook.Provider {
	return facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), "/foo", signReq, "email")
}
