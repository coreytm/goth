// Package facebook implements the OAuth2 protocol for authenticating users through Facebook.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package facebook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/golang/glog"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://www.facebook.com/dialog/oauth"
	tokenURL        string = "https://graph.facebook.com/oauth/access_token"
	endpointProfile string = "https://graph.facebook.com/me?fields=email,first_name,last_name,link,bio,id,name,picture,location"
)

// New creates a new Facebook provider, and sets up important connection details.
// You should always call `facebook.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, signRequests bool, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		SignRequests: signRequests,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Facebook.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config

	// SignedRequests is used to specify whether or not the provider is expecting signed requests
	SignRequests bool
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "facebook"
}

// Debug is a no-op for the facebook package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Facebook for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// GetProof will create a sha256 hash of the user access token using the provider secret
func (p *Provider) GetProof(session goth.Session) ([]byte, error) {
	sess := session.(*Session)
	h := hmac.New(sha256.New, []byte(p.Secret))

	_, err := h.Write([]byte(sess.AccessToken))
	if err != nil {
		return nil, err
	}

	proof := h.Sum(nil)

	return proof, nil
}

// FetchUser will go to Facebook and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
		ExpiresAt:   sess.ExpiresAt,
	}

	var resp *http.Response

	if p.SignRequests {
		proof, err := p.GetProof(session)
		if err != nil {
			return user, err
		}

		url := fmt.Sprintf(endpointProfile+"&appsecret_proof=%x", proof)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return user, err
		}

		glog.Infof("Making a Signed Request to: %s", url)

		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", sess.AccessToken))
		c := http.DefaultClient
		resp, err = c.Do(req)
		if err != nil {
			return user, err
		}
	} else {
		resp, err := http.Get(endpointProfile + "&access_token=" + url.QueryEscape(sess.AccessToken))
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			return user, err
		}
	}

	defer resp.Body.Close()

	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Bio     string `json:"bio"`
		Name    string `json:"name"`
		Link    string `json:"link"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
		Location struct {
			Name string `json:"name"`
		} `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Name
	user.Email = u.Email
	user.Description = u.Bio
	user.AvatarURL = u.Picture.Data.URL
	user.UserID = u.ID
	user.Location = u.Location.Name

	return err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{
			"email",
		},
	}

	defaultScopes := map[string]struct{}{
		"email": {},
	}

	for _, scope := range scopes {
		if _, exists := defaultScopes[scope]; !exists {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

//RefreshToken refresh token is not provided by facebook
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by facebook")
}

//RefreshTokenAvailable refresh token is not provided by facebook
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
