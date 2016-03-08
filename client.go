package httpauth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Signer is an interface which defines the Sign method.
type Signer interface {
	// Sign adds a signature to the http.Request, returning an error
	// if there was a problem...
	Sign(r *http.Request) error
}

// BasicAuthSigner is a basic Signer which adds Basic HTML Authentication headers
// to Requests.
type BasicAuthSigner struct {
	User, Pass string
}

// Sign implements Signer.
func (b BasicAuthSigner) Sign(r *http.Request) error {
	r.SetBasicAuth(b.User, b.Pass)
	return nil
}

// NewClient creates a new Client with the http.Client as underlying transport and
// Signer.
func NewClient(c *http.Client, s Signer) *Client {
	return &Client{
		Client: c,
		Signer: s,
	}
}

// Client is a light wrapper around http.Client which calls Sign on each request
// before it is used.
type Client struct {
	*http.Client
	Signer
}

// Do sends an HTTP request and returns an HTTP response.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.Sign(req); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Head(url string) (*http.Response, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post issues a POST request via the Do function.
func (c *Client) Post(url string, bodyType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", bodyType)
	return c.Do(req)
}

// PostForm issues a POST request via the Do function.
func (c *Client) PostForm(url string, data url.Values) (*http.Response, error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// Do sends an HTTP request with the provided http.Client and returns an HTTP response.
// If the client is nil, http.DefaultClient is used.
func Do(s Signer, client *http.Client, req *http.Request) (*http.Response, error) {
	if err := s.Sign(req); err != nil {
		return nil, err
	}

	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

// Get issues a GET request via the Do function.
func Get(s Signer, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return Do(s, client, req)
}

// Head issues a HEAD request via the Do function.
func Head(s Signer, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return Do(s, client, req)
}

// Post issues a POST request via the Do function.
func Post(s Signer, client *http.Client, url string, bodyType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", bodyType)
	return Do(s, client, req)
}

// PostForm issues a POST request via the Do function.
func PostForm(s Signer, client *http.Client, url string, data url.Values) (*http.Response, error) {
	return Post(s, client, url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
