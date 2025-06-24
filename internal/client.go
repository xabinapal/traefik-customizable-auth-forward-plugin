package internal

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
)

type Client struct {
	client *http.Client
	config *ConfigParsed
}

func NewClient(config *ConfigParsed) (*Client, error) {
	httpClient := &http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			// Don't follow redirects
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
		config: config,
	}, nil
}

func (c *Client) CreateAuthRequest(req *http.Request) (*http.Request, error) {
	method := http.MethodGet
	if c.config.PreserveRequestMethod {
		method = req.Method
	}

	fmt.Printf("creating auth request\n")

	authReq, err := http.NewRequestWithContext(req.Context(), method, c.config.Address, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating auth request: %w", err)
	}

	CopyHeaders(req.Header, authReq.Header, c.config.AuthRequestHeaders)
	CopyHeadersRegex(req.Header, authReq.Header, c.config.AuthRequestHeadersRegex)

	CopyCookies(req, authReq, c.config.AuthRequestCookies)

	c.setAuthRequestHeaders(req, authReq)

	if c.config.ForwardBody {
		c.setAuthRequestBody(req, authReq)
	}

	return authReq, nil
}

func (c *Client) setAuthRequestHeaders(req *http.Request, authReq *http.Request) {
	absoluteUrl := url.URL{}

	forwardedFor := req.Header.Get("X-Forwarded-For")
	if forwardedFor != "" && c.config.TrustForwardHeader {
		authReq.Header.Set(c.config.AuthRequestForHeader, forwardedFor)
	} else if req.RemoteAddr != "" {
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			authReq.Header.Set(c.config.AuthRequestForHeader, clientIP)
		}
	}

	forwardedMethod := req.Header.Get("X-Forwarded-Method")
	if forwardedMethod != "" && c.config.TrustForwardHeader {
		authReq.Header.Set(c.config.AuthRequestMethodHeader, forwardedMethod)
	} else if req.Method != "" {
		authReq.Header.Set(c.config.AuthRequestMethodHeader, req.Method)
	}

	forwardedProto := req.Header.Get("X-Forwarded-Proto")
	if forwardedProto != "" && c.config.TrustForwardHeader {
		absoluteUrl.Scheme = forwardedProto
	} else if req.TLS != nil {
		absoluteUrl.Scheme = "https"
	} else {
		absoluteUrl.Scheme = "http"
	}

	forwardedHost := req.Header.Get("X-Forwarded-Host")
	if forwardedHost != "" && c.config.TrustForwardHeader {
		absoluteUrl.Host = forwardedHost
	} else if req.Host != "" {
		absoluteUrl.Host = req.Host
	}

	forwardedUri := req.Header.Get("X-Forwarded-Uri")
	if forwardedUri != "" && c.config.TrustForwardHeader {
		absoluteUrl.Path = forwardedUri
	} else if req.RequestURI != "" {
		absoluteUrl.Path = req.RequestURI
	}

	authReq.Header.Set(c.config.AuthRequestProtoHeader, absoluteUrl.Scheme)
	authReq.Header.Set(c.config.AuthRequestHostHeader, absoluteUrl.Host)
	authReq.Header.Set(c.config.AuthRequestUriHeader, absoluteUrl.Path)

	if c.config.AbsoluteUrlHeader != "" {
		authReq.Header.Set(c.config.AuthRequestAbsoluteUrlHeader, absoluteUrl.String())
	}
}

func (c *Client) setAuthRequestBody(req *http.Request, authReq *http.Request) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return
		}

		var truncatedBody []byte
		if c.config.MaxBodySize >= 0 && int64(len(body)) > c.config.MaxBodySize {
			truncatedBody = body[:c.config.MaxBodySize]
		} else {
			truncatedBody = body
		}

		authReq.Body = io.NopCloser(bytes.NewReader(truncatedBody))
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}
