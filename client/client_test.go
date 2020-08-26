package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"testing"
	"time"
)

type MockClient struct {
	t       *testing.T
	DoFunc  func(req *http.Request) (*http.Response, error)
	GetFunc func(dest string) (*http.Response, error)
}

func (mc *MockClient) Do(req *http.Request) (*http.Response, error) {
	return mc.DoFunc(req)
}
func (mc *MockClient) Get(dest string) (*http.Response, error) {
	return mc.GetFunc(dest)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func getResponse(statusCode int, body []byte) *http.Response {
	r := ioutil.NopCloser(bytes.NewReader(body))
	return &http.Response{StatusCode: statusCode, Body: r}
}

func match(pattern, target string) bool {
	match, err := regexp.Match(pattern, []byte(target))
	if err != nil {
		return false
	}
	return match
}

func parsePath(dest string, responseCodes [3]int) (*http.Response, error) {
	token := RandStringRunes(10)
	tokenResponse := TokenResponse{
		AccessToken: token,
		ExpiresIn:   1,
	}

	switch {
	case match("mockta.local", dest):
		switch {
		case match("well-known", dest):
			// build response JSON
			body, _ := json.Marshal(OAuthWellKnown{TokenEndpoint: "https://mockta.local/token"})
			// create a new reader with that JSON
			return getResponse(responseCodes[0], body), nil
		case match("token", dest):
			body, _ := json.Marshal(tokenResponse)
			return getResponse(responseCodes[1], body), nil
		}
	case match("demo.local", dest):
		return getResponse(responseCodes[2], []byte{}), nil
	}
	return nil, errors.New("Failed")
}

var validResponses = [3]int{200, 200, 200}

func validDo(req *http.Request) (*http.Response, error) {

	host := req.URL.String()
	return parsePath(host, validResponses)
}

func validGet(dest string) (*http.Response, error) {
	return parsePath(dest, validResponses)
}

func TestOktaErrors(t *testing.T) {
	mc := MockClient{t: t}
	mc.DoFunc = func(req *http.Request) (*http.Response, error) {
		host := req.URL.String()
		rc := [3]int{200, 429, 200}
		return parsePath(host, rc)
	}
	mc.GetFunc = func(dest string) (*http.Response, error) {
		rc := [3]int{200, 429, 200}
		return parsePath(dest, rc)
	}
	config := ClientConfig{
		Scopes:     []string{"thing"},
		OktaDomain: "mockta.local",
		HTTPClient: &mc,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_, err = client.Get("demo.local")
	if err == nil {
		t.Fatal("Expected error got nil")
	}

	client, err = NewClient(config)
	mc.DoFunc = func(req *http.Request) (*http.Response, error) {
		host := req.URL.String()
		rc := [3]int{200, 401, 200}
		return parsePath(host, rc)
	}
	mc.GetFunc = func(dest string) (*http.Response, error) {
		rc := [3]int{200, 401, 200}
		return parsePath(dest, rc)
	}
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_, err = client.Get("demo.local")
	if err == nil {
		t.Fatal("Expected error got nil")
	}
}

// TestGetToken tests the getToken function for goroutine safety
func TestGetToken(t *testing.T) {
	mc := MockClient{t: t}
	mc.DoFunc = validDo
	mc.GetFunc = validGet
	config := ClientConfig{
		Scopes:     []string{"thing"},
		OktaDomain: "mockta.local",
		HTTPClient: &mc,
	}

	client, err := NewClient(config)

	if err != nil {
		t.Fatalf("Failed: %s", err)
	}

	// Test surge of requests these should all use the same key
	result := testConcurrency(client, 0, 100, t)
	if len(result) > 1 {
		t.Fatalf("Concurrency Test 1 Failed: got %d, want 1\n", len(result))
	}

	// Test renewals
	result = testConcurrency(client, 1000, 10, t)
	if len(result) != 10 {
		t.Fatalf("Concurrency Test 2 Failed: got %d, want 10\n", len(result))
	}
}

type streamResult struct {
	resp  *http.Response
	token string
}

func testConcurrency(client *Client, interval, threads int, t *testing.T) map[string]int {
	respCh := make(chan streamResult, threads+1)
	errCh := make(chan error, threads+1)
	for i := 0; i < threads; i++ {
		time.Sleep(time.Duration(interval) * time.Millisecond)
		func(r chan streamResult, e chan error) {

			resp, err := client.Get("demo.local")
			if err != nil {
				t.Fatalf("Failed: %s", err)
			}
			respCh <- streamResult{resp, client.token.AccessToken}
		}(respCh, errCh)
	}

	keys := map[string]int{}
	count := 0
	for respResult := range respCh {
		if respResult != (streamResult{}) {
			keys[respResult.token]++
			count++
		}
		if count >= threads {
			report := "Key Usage:\n"
			for k, v := range keys {
				report += fmt.Sprintf("%s: %d\n", k, v)
			}
			t.Log(report)
			close(respCh)
			break
		}
	}

	select {
	case e := <-errCh:
		if e != nil {
			t.Fatalf("Failed %v", e)
		}
	default:
	}
	return keys
}
