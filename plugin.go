package traefik_customizable_auth_forward_plugin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal"
)

const (
	defaultTimeout      = 30 * time.Second
	defaultHeaderPrefix = "X-Forwarded"
)

type Plugin struct {
	next   http.Handler
	name   string
	config *internal.Config
	client *internal.Client

	headersRegex *regexp.Regexp
}

func CreateConfig() *internal.Config {
	return &internal.Config{
		Address: "",
		Timeout: defaultTimeout,
		TLS: &internal.TLSConfig{
			CA:                 "",
			Cert:               "",
			Key:                "",
			InsecureSkipVerify: false,
		},

		PreserveRequestMethod: false,

		HeaderPrefix:       defaultHeaderPrefix,
		TrustForwardHeader: false,

		AuthRequestHeaders:      []string{},
		AuthRequestHeadersRegex: "",
		AddAuthCookiesToRequest: []string{},

		AuthResponseHeaders:      []string{},
		AuthResponseHeadersRegex: "",
		AddAuthCookiesToResponse: []string{},
		PreserveLocationHeader:   false,

		ForwardBody: false,
		MaxBodySize: -1,
	}
}

func New(ctx context.Context, next http.Handler, config *internal.Config, name string) (http.Handler, error) {
	// Validate config
	if config.Address == "" {
		return nil, fmt.Errorf("address cannot be empty")
	}

	// Create HTTP client with custom configuration
	client, err := internal.CreateClient(config)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %v", err)
	}

	// Compile auth response headers regex
	var headersRegex *regexp.Regexp
	if config.AuthResponseHeadersRegex != "" {
		re, err := regexp.Compile(config.AuthResponseHeadersRegex)
		if err != nil {
			return nil, fmt.Errorf("error compiling auth response headers regex: %v", err)
		}
		headersRegex = re
	}

	plugin := &Plugin{
		next:         next,
		name:         name,
		config:       config,
		client:       client,
		headersRegex: headersRegex,
	}

	return plugin, nil
}

func (cfa *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Create a request to the auth service
	authReq, err := cfa.client.CreateAuthRequest(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("sending auth request")

	// Send a request to the auth service
	authRes, err := cfa.client.Do(authReq)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	defer authRes.Body.Close()

	fmt.Printf("auth request returned status code %v\n", authRes.StatusCode)

	// If auth service returns non-2xx status, forward its response
	if authRes.StatusCode < http.StatusOK || authRes.StatusCode >= http.StatusMultipleChoices {
		fmt.Printf("forwarding auth response to client\n")

		location := authRes.Header.Get("Location")
		if location != "" {
			if cfa.config.PreserveLocationHeader {
				locationUrl, err := url.Parse(location)
				if err != nil {
					return
				}

				if !locationUrl.IsAbs() {
					addressURL, err := url.Parse(cfa.config.Address)
					if err != nil {
						return
					}

					locationUrl.Scheme = addressURL.Scheme
					locationUrl.Host = addressURL.Host

					location = locationUrl.String()
				}
			}

			rw.Header().Add("Location", location)
		}

		rw.WriteHeader(authRes.StatusCode)

		if _, err := io.Copy(rw, authRes.Body); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}

	cfa.attachAuthResponseHeaders(req, authRes)
	cfa.attachAuthResponseCookies(req, authRes)

	cfa.next.ServeHTTP(rw, req)
}

func (cfa *Plugin) attachAuthResponseHeaders(req *http.Request, authRes *http.Response) {
	for _, header := range cfa.config.AuthResponseHeaders {
		header := http.CanonicalHeaderKey(header)

		if values := authRes.Header.Values(header); len(values) > 0 {
			req.Header.Add(header, values[0])
		}
	}

	if cfa.headersRegex != nil {
		for headerKey, headerValues := range authRes.Header {
			headerKey = http.CanonicalHeaderKey(headerKey)

			if cfa.headersRegex.MatchString(headerKey) {
				req.Header[headerKey] = headerValues
			}
		}
	}
}

func (cfa *Plugin) attachAuthResponseCookies(req *http.Request, authRes *http.Response) {
	// TODO
}
