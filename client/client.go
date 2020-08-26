package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const grant_type = "client_credentials"

func encodeCredentials(ID, Secret string) string {
	msg := ID + ":" + Secret
	return base64.StdEncoding.EncodeToString([]byte(msg))
}

func NewClient(config ClientConfig) (client *Client, err error) {

	// use default http.Client if non-was passed
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{}
	}
	// populate auth server url or use default
	authServer := "/"
	if config.OktaAuthServerID != "" {
		authServer = authServer + config.OktaAuthServerID + "/"
	} else {
		authServer = authServer + "default/"
	}

	// create well-known oauth url and request metadata
	wellKnownURL := "https://" + config.OktaDomain + "/oauth2" + authServer + ".well-known/oauth-authorization-server"
	resp, err := config.HTTPClient.Get(wellKnownURL)
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

	// parse token uri from well known response
	tURL, err := url.Parse(wellKnown.TokenEndpoint)
	if err != nil {
		return nil, err
	}

	key := encodeCredentials(config.ID, config.Secret)

	scopes := strings.Join(config.Scopes, "+")

	return &Client{
		tokenEndpoint: *tURL,
		key:           key,
		scopes:        scopes,
		config:        config,
	}, nil
}

func (c *Client) lock() {
	c.mux.Lock()
}

func (c *Client) unlock() {
	c.mux.Unlock()
}

func (c *Client) Get(dest string) (*http.Response, error) {

	token, err := c.getToken()
	if err != nil {
		return nil, err
	}

	if token == "" {
		return nil, fmt.Errorf("Failed to get okta token")
	}
	req, _ := http.NewRequest(http.MethodGet, dest, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	return c.config.HTTPClient.Do(req)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	token, err := c.getToken()
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("Failed to get okta token")
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	return c.config.HTTPClient.Do(req)
}

func (c *Client) getToken() (string, error) {
	if c.token.AccessToken == "" || time.Now().After(c.token.Expiry) {
		c.lock()
		if c.request == nil {
			errCh := make(chan error, 3)
			c.request = &tokenRequest{doneCh: make(chan struct{}), errCh: errCh}

			logger := log.WithFields(log.Fields{"id": c.config.ID, "method": http.MethodPost})
			go func() {
				defer close(errCh)
				defer c.request.done()
				dest := c.tokenEndpoint
				data := url.Values{}
				data.Set("scope", c.scopes)
				data.Add("grant_type", grant_type)
				dest.RawQuery = data.Encode()

				req, _ := http.NewRequest(http.MethodPost, dest.String(), strings.NewReader(data.Encode()))

				req.Header.Add("Accept", "application/json")
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", c.key))
				req.Header.Add("Cache-Control", "no-cache")
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

				resp, err := c.config.HTTPClient.Do(req)
				if err != nil {
					logger.Errorf("Request for new token failed: %v", err)
					c.request.errCh <- err
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode >= 400 {
					// TODO: rate limiting and backoff for hitting okta
					var errResp []byte
					json.NewDecoder(resp.Body).Decode(&errResp)
					c.request.errCh <- fmt.Errorf("API Error from Okta: %v", resp)
					return
				}
				t := time.Now()
				var tokenResp TokenResponse
				if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
					logger.Errorf("Failed to decode token response: %v", err)
					c.request.errCh <- err
					return
				}

				c.lock()
				tokenResp.Expiry = t.Add(time.Second * time.Duration(tokenResp.ExpiresIn))
				c.unlock()
				c.token = tokenResp

				c.request = nil
			}()
		}
		request := c.request
		c.unlock()

		for err := range request.errCh {
			if err != nil {
				return "", err
			}
		}

		select {
		case <-request.wait():
			return c.token.AccessToken, nil
		}
	}
	return c.token.AccessToken, nil
}
