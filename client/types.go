package client

import (
	"sync"
	"time"
	"net/url"
	"net/http"
	"errors"
)


type ErrorResponse struct {
	ErrorCode	string `json:"errorCode"`
	ErrorSummary	string `json:"errorSummary"`
	ErrorLink	string `json:"errorLink"`
	ErrorId		string `json:"errorId"`
	ErrorCauses	string `json:"errorCauses"`
}
// OktaWellKnown represents the valuse from an okta authserver .well-known endpoint
type OAuthWellKnown struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	UserinfoEndpoint                          string   `json:"userinfo_endpoint"`
	RegistrationEndpoint                      string   `json:"registration_endpoint"`
	JwksURI                                   string   `json:"jwks_uri"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	ResponseModesSupported                    []string `json:"response_modes_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                           []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                           []string `json:"claims_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpoint                        string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported"`
}


// Client implements an okta client credentials flow client
type Client struct {
	mux sync.Mutex
	request *tokenRequest
	tokenEndpoint url.URL
	key string
	scopes string
	config ClientConfig
	token TokenResponse
}


type MockClient struct {}

func (mc *MockClient) Do(req *http.Request) (*http.Response, error){
	return nil, errors.New("Failed")
}

func (mc *MockClient) Get(dest string) (*http.Response, error){
	return nil, errors.New("Failed")
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
	Get(dest string) (*http.Response, error)
}

type ClientConfig struct {
	Scopes []string
	ID string
	Secret string
	OktaDomain string
	OktaAuthServerID string
	HTTPClient HTTPClient
}
type tokenRequest struct {
	doneCh chan struct{}
	errCh chan error
}

func (t *tokenRequest) done() {
	close(t.doneCh)
}

func (t *tokenRequest) wait() <-chan struct{} {
	return t.doneCh
}

// TokenResponse is a representation of a valid response body from the /token endpoint
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int `json:"expires_in"`
	Expiry time.Time
	Scope string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken string `json:"id_token"`
}
