package internal

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

type Client struct {
	client *http.Client

	address        string
	preserveMethod bool
}

func CreateClient(config *Config) *Client {
	httpClient := &http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: config.Timeout,
	}

	if config.TLS != nil {
		tlsConfig := &tls.Config{
			MinVersion:         config.TLS.MinVersion,
			MaxVersion:         config.TLS.MaxVersion,
			InsecureSkipVerify: config.TLS.InsecureSkipVerify,
		}

		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		httpClient.Transport = transport
	}

	return &Client{
		client: httpClient,

		address:        config.Address,
		preserveMethod: config.PreserveRequestMethod,
	}
}

func (c *Client) CreateAuthRequest(req *http.Request) (*http.Request, error) {
	method := http.MethodGet
	if c.preserveMethod {
		method = req.Method
	}

	fmt.Printf("creating auth request to %s with method %s\n", c.address, method)

	authReq, err := http.NewRequestWithContext(req.Context(), method, c.address, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating forward request: %w", err)
	}

	return authReq, nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}
