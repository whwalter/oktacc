package client

import (
	"net/http"
	"net/url"
	"encoding/json"

	log "github.com/sirupsen/logrus"
)


func NewClient(oktaDomain, oktaAuthServerID, clientID, clientSecret string, httpClient *http.Client) (client *Client, err error) {

	authServer := "/"
	if oktaAuthServerID != "" { 
		authServer = authServer + oktaAuthServerID + "/"
	} else {
		authServer = authServer + "default/" 
	}
	wellKnownURL := "https://" + oktaDomain + authServer + ".well-known/oauth-authorization-server"
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
		return nil, fmt.Errorf("No token enpoint detected from well-known: %s", wellKnown)
	}

	return Client{
		tokenEndpoint: url.Parse(wellKnown.TokenEndpoint),
		id: clientID,
		secret: clientSecret,
		httpClient: httpClient,
	}
}


func (c *Client) GetToken() {}


func (c *Client) Lock(){
	c.mux.Lock()
}

func (c *Client) Unlock(){
	c.mux.Unlock()
}
