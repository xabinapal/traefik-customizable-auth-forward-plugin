package internal

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
)

type Client struct {
	client *http.Client

	address string

	preserveMethod bool

	headerPrefix       string
	trustForwardHeader bool

	authRequestHeaders      []string
	authRequestHeadersRegex *regexp.Regexp
	addAuthCookiesToRequest []string

	forwardBody bool
	maxBodySize int64
}

func CreateClient(config *Config) (*Client, error) {
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

	var authRequestHeadersRegex *regexp.Regexp
	if config.AuthRequestHeadersRegex != "" {
		re, err := regexp.Compile(config.AuthRequestHeadersRegex)
		if err != nil {
			return nil, fmt.Errorf("error compiling auth request headers regex: %w", err)
		}
		authRequestHeadersRegex = re
	}

	return &Client{
		client: httpClient,

		address: config.Address,

		preserveMethod: config.PreserveRequestMethod,

		headerPrefix:       config.HeaderPrefix,
		trustForwardHeader: config.TrustForwardHeader,

		authRequestHeaders:      config.AuthRequestHeaders,
		authRequestHeadersRegex: authRequestHeadersRegex,
		addAuthCookiesToRequest: config.AddAuthCookiesToRequest,

		forwardBody: config.ForwardBody,
		maxBodySize: config.MaxBodySize,
	}, nil
}

func (c *Client) CreateAuthRequest(req *http.Request) (*http.Request, error) {
	method := http.MethodGet
	if c.preserveMethod {
		method = req.Method
	}

	fmt.Printf("creating auth request\n")

	authReq, err := http.NewRequestWithContext(req.Context(), method, c.address, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating auth request: %w", err)
	}

	c.attachForwardHeaders(authReq, req)

	c.attachRequestHeaders(authReq, req)
	c.attachRequestCookies(authReq, req)

	if c.forwardBody {
		c.attachRequestBody(authReq, req)
	}

	return authReq, nil
}

func (c *Client) attachForwardHeaders(authReq *http.Request, req *http.Request) {
	forHeader := c.headerPrefix + "-For"
	forwardedFor := req.Header.Get("X-Forwarded-For")
	if forwardedFor != "" && c.trustForwardHeader {
		authReq.Header.Set(forHeader, forwardedFor)
	} else if req.RemoteAddr != "" {
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			authReq.Header.Set(forHeader, clientIP)
		}
	}

	methodHeader := c.headerPrefix + "-Method"
	forwardedMethod := req.Header.Get("X-Forwarded-Method")
	if forwardedMethod != "" && c.trustForwardHeader {
		authReq.Header.Set(methodHeader, forwardedMethod)
	} else if req.Method != "" {
		authReq.Header.Set(methodHeader, req.Method)
	}

	protoHeader := c.headerPrefix + "-Proto"
	forwardedProto := req.Header.Get("X-Forwarded-Proto")
	if forwardedProto != "" && c.trustForwardHeader {
		authReq.Header.Set(protoHeader, forwardedProto)
	} else if req.TLS != nil {
		authReq.Header.Set(protoHeader, "https")
	} else {
		authReq.Header.Set(protoHeader, "http")
	}

	hostHeader := c.headerPrefix + "-Host"
	forwardedHost := req.Header.Get("X-Forwarded-Host")
	if forwardedHost != "" && c.trustForwardHeader {
		authReq.Header.Set(hostHeader, forwardedHost)
	} else if req.Host != "" {
		authReq.Header.Set(hostHeader, req.Host)
	}

	uriHeader := c.headerPrefix + "-Uri"
	forwardedUri := req.Header.Get("X-Forwarded-Uri")
	if forwardedUri != "" && c.trustForwardHeader {
		authReq.Header.Set(uriHeader, forwardedUri)
	} else if req.RequestURI != "" {
		authReq.Header.Set(uriHeader, req.RequestURI)
	}
}

func (c *Client) attachRequestHeaders(authReq *http.Request, req *http.Request) {
	for _, header := range c.authRequestHeaders {
		if values := req.Header.Get(header); values != "" {
			authReq.Header.Set(header, values)
		}
	}

	if c.authRequestHeadersRegex != nil {
		for headerKey, headerValues := range req.Header {
			if c.authRequestHeadersRegex.MatchString(headerKey) {
				authReq.Header[headerKey] = headerValues
			}
		}
	}
}

func (c *Client) attachRequestCookies(authReq *http.Request, req *http.Request) {
	for _, cookieName := range c.addAuthCookiesToRequest {
		if cookie, err := req.Cookie(cookieName); err == nil {
			authReq.AddCookie(cookie)
		}
	}
}

func (c *Client) attachRequestBody(authReq *http.Request, req *http.Request) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return
		}

		var truncatedBody []byte
		if c.maxBodySize >= 0 && int64(len(body)) > c.maxBodySize {
			truncatedBody = body[:c.maxBodySize]
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
