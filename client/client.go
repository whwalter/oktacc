package client

import (
	"net/http"
	"net/url"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"time"
	"strings"

//	log "github.com/sirupsen/logrus"
)

const grant_type = "client_credentials"

func NewClient(oktaDomain, oktaAuthServerID, clientID, clientSecret string, httpClient *http.Client) (client *Client, err error) {

	authServer := "/"
	if oktaAuthServerID != "" { 
		authServer = authServer + oktaAuthServerID + "/"
	} else {
		authServer = authServer + "default/" 
	}
	wellKnownURL := "https://" + oktaDomain + "/oauth2" +  authServer + ".well-known/oauth-authorization-server"
	fmt.Println(wellKnownURL)
	resp, err := http.Get(wellKnownURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var wellKnown OAuthWellKnown
	if err := json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		return nil, fmt.Errorf("Error reading .well-known endpoint: %s", err)
	}

	if wellKnown.TokenEndpoint == "" {
		return nil, fmt.Errorf("No token enpoint detected from well-known: %v", wellKnown)
	}

	tURL, err := url.Parse(wellKnown.TokenEndpoint)
	if err != nil {
		return nil, err
	}
	return &Client{
		tokenEndpoint: *tURL,
		id: clientID,
		secret: clientSecret,
		httpClient: httpClient,
	}, nil
}


func (c *Client) GetToken(scopes []string) (string, error){
	if c.token.AccessToken == "" {
		// get new token
		err := newToken(c, scopes)
		if err != nil {
			return "", err
		}
	}

	if time.Now().After(c.token.Expiry) {
		// get new token
		err := newToken(c, scopes)
		if err != nil {
			return "", err
		}
	}

	return c.token.AccessToken, nil
	
}

func newToken(c *Client, scopes []string) error {

	c.lock()
	defer c.unlock()
	dest := c.tokenEndpoint
	data := url.Values{}
	data.Set("scope", strings.Join(scopes, "+"))
	data.Add("grant_type", grant_type)
	dest.RawQuery = data.Encode()

	req, err := http.NewRequest(http.MethodPost, dest.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encodeCredentials(c.id, c.secret)))
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	t := time.Now()
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	tokenResp.Expiry = t.Add(time.Second * time.Duration(tokenResp.ExpiresIn))
	c.token = tokenResp

	return nil

}

func encodeCredentials(ID, Secret string) string {
	msg := ID + ":" + Secret
	return base64.StdEncoding.EncodeToString([]byte(msg))	
}

func (c *Client) lock(){
	c.mux.Lock()
}

func (c *Client) unlock(){
	c.mux.Unlock()
}
