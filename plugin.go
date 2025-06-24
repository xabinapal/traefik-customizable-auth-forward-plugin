package traefik_customizable_auth_forward_plugin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/httputil"
)

const (
	defaultTimeout               = "30s"
	defaultTlsMinVersion         = 12
	defaultTlsMaxVersion         = 13
	defaultTlsInsecureSkipVerify = false

	defaultPreserveRequestMethod = false

	defaultHeaderPrefix       = "X-Forwarded"
	defaultAbsoluteUrlHeader  = ""
	defaultTrustForwardHeader = false

	defaultAuthRequestHeadersRegex = ""

	defaultAuthResponseHeadersRegex = ""
	defaultPreserveLocationHeader   = false

	defaultForwardBody = false
	defaultMaxBodySize = -1
)

type Plugin struct {
	name string
	next http.Handler

	config *internal.ConfigParsed
	client *internal.Client
}

func CreateConfig() *internal.Config {
	return &internal.Config{
		Address: "",
		Timeout: defaultTimeout,
		TLS: &internal.TLSConfig{
			CA:                 "",
			Cert:               "",
			Key:                "",
			MinVersion:         defaultTlsMinVersion,
			MaxVersion:         defaultTlsMaxVersion,
			InsecureSkipVerify: defaultTlsInsecureSkipVerify,
		},

		PreserveRequestMethod: defaultPreserveRequestMethod,

		HeaderPrefix:       defaultHeaderPrefix,
		AbsoluteUrlHeader:  defaultAbsoluteUrlHeader,
		TrustForwardHeader: defaultTrustForwardHeader,

		AuthRequestHeaders:      []string{},
		AuthRequestHeadersRegex: defaultAuthRequestHeadersRegex,
		AuthRequestCookies:      []string{},

		AuthResponseHeaders:      []string{},
		AuthResponseHeadersRegex: defaultAuthResponseHeadersRegex,
		AddAuthCookiesToResponse: []string{},
		PreserveLocationHeader:   defaultPreserveLocationHeader,

		StatusCodeGlobalMappings: map[int]int{},
		StatusCodePathMappings:   []internal.PathMappingConfig{},

		ForwardBody: defaultForwardBody,
		MaxBodySize: defaultMaxBodySize,
	}
}

func New(ctx context.Context, next http.Handler, config *internal.Config, name string) (http.Handler, error) {
	configParsed, err := internal.ParseConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}

	// Create HTTP client with custom configuration
	client, err := internal.NewClient(configParsed)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}

	plugin := &Plugin{
		name: name,
		next: next,

		config: configParsed,
		client: client,
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
	defer func() {
		if closeErr := authRes.Body.Close(); closeErr != nil {
			fmt.Printf("error closing auth response body: %v\n", closeErr)
		}
	}()

	fmt.Printf("auth request returned status code %v\n", authRes.StatusCode)

	// If auth service returns non-2xx status, forward its response
	if authRes.StatusCode < http.StatusOK || authRes.StatusCode >= http.StatusMultipleChoices {
		mappedStatusCode := mapStatusCode(req.URL.Path, authRes.StatusCode, cfa.config.StatusCodeGlobalMappings, cfa.config.StatusCodePathMappings)

		fmt.Printf("forwarding auth response to client with status code %v\n", mappedStatusCode)

		// Copy all headers from auth response to preserve them
		for key, values := range authRes.Header {
			for _, value := range values {
				rw.Header().Add(key, value)
			}
		}

		location := authRes.Header.Get("Location")
		if location != "" {
			if cfa.config.PreserveLocationHeader {
				locationURL, err := url.Parse(location)
				if err != nil {
					return
				}

				if !locationURL.IsAbs() {
					addressURL, err := url.Parse(cfa.config.Address)
					if err != nil {
						return
					}

					locationURL.Scheme = addressURL.Scheme
					locationURL.Host = addressURL.Host

					location = locationURL.String()
				}
			}

			rw.Header().Set("Location", location)
		}

		rw.WriteHeader(mappedStatusCode)

		if _, err := io.Copy(rw, authRes.Body); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		return
	}

	responseModifier := httputil.NewResponseModifier(rw)

	httputil.CopyHeaders(authRes.Header, req.Header, cfa.config.AuthResponseHeaders)
	httputil.CopyHeadersRegex(authRes.Header, req.Header, cfa.config.AuthResponseHeadersRegex)

	httputil.CopyCookies(authRes, req, cfa.config.AddAuthCookiesToResponse)
	httputil.CopyCookies(authRes, responseModifier, cfa.config.AddAuthCookiesToResponse)

	cfa.next.ServeHTTP(responseModifier, req)
}

func mapStatusCode(path string, statusCode int, globalMappings map[int]int, pathMappings []internal.PathMappingConfig) int {
	var longestMatch string
	var longestMatchStatusCode int
	var longestPathLen int

	for _, mapping := range pathMappings {
		if strings.HasPrefix(path, mapping.Path) && len(mapping.Path) > longestPathLen {
			if mappedCode, exists := mapping.Mappings[statusCode]; exists {
				longestMatch = mapping.Path
				longestMatchStatusCode = mappedCode
				longestPathLen = len(mapping.Path)
			}
		}

		fmt.Printf("\n")
	}

	if longestMatch != "" {
		fmt.Printf("found path mapping %v -> %v\n", longestMatch, longestMatchStatusCode)
		return longestMatchStatusCode
	}

	if mappedCode, exists := globalMappings[statusCode]; exists {
		fmt.Printf("found global mapping %v -> %v\n", path, mappedCode)
		return mappedCode
	}

	return statusCode
}
