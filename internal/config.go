package internal

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	// Address is the URL of the authentication service
	Address string `json:"address,omitempty"`

	// Timeout for auth service requests
	Timeout string `json:"timeout,omitempty"`

	// TLS configuration for secure connection to auth service
	TLS *TLSConfig `json:"tls,omitempty"`

	// PreserveRequestMethod indicates whether to preserve the original request method
	PreserveRequestMethod bool `json:"preserveRequestMethod,omitempty"`

	// HeaderPrefix allows customization of the authentication header names
	// Default is "X-Forwarded" which results in standard headers like "X-Forwarded-Host"
	// Setting this to "X-Original" would result in "X-Original-Host", etc.
	HeaderPrefix string `json:"headerPrefix,omitempty"`

	// AbsoluteUrlHeader is the name of the header to copy the absolute URL to the auth request
	AbsoluteUrlHeader string `json:"absoluteUrlHeader,omitempty"`

	// TrustForwardHeader indicates whether to use existing forward headers in the original request
	// as the values for the authentication headers in the auth request
	TrustForwardHeader bool `json:"trustForwardHeader,omitempty"`

	// AuthRequestHeaders is a list of headers to copy from original request to auth request
	AuthRequestHeaders []string `json:"authRequestHeaders,omitempty"`

	// AuthRequestHeadersRegex is a regex pattern to match headers to copy from original request
	AuthRequestHeadersRegex string `json:"authRequestHeadersRegex,omitempty"`

	// AddAuthCookiesToRequest is a list of cookie names to copy from original request to auth request
	AuthRequestCookies []string `json:"authRequestCookies,omitempty"`

	// AuthResponseHeaders is a list of headers to copy from auth response to the forwarded request
	AuthResponseHeaders []string `json:"authResponseHeaders,omitempty"`

	// AuthResponseHeadersRegex is a regex pattern to match headers to copy from auth response
	AuthResponseHeadersRegex string `json:"authResponseHeadersRegex,omitempty"`

	// AddAuthCookiesToResponse is a list of cookie names to copy from auth response
	AddAuthCookiesToResponse []string `json:"addAuthCookiesToResponse,omitempty"`

	// PreserveLocationHeader indicates whether to preserve the Location header from auth response
	PreserveLocationHeader bool `json:"preserveLocationHeader,omitempty"`

	// ForwardBody indicates whether to forward the request body to the auth service
	ForwardBody bool `json:"forwardBody,omitempty"`

	// MaxBodySize sets the maximum size of the body to forward (default: 64KB)
	MaxBodySize int64 `json:"maxBodySize,omitempty"`

	// StatusCodeGlobalMappings allows to modify authentication service status codes
	StatusCodeGlobalMappings map[int]int `json:"statusCodeGlobalMappings,omitempty"`

	// StatusCodePathMappings allows to modify authentication service status codes based on the request path
	StatusCodePathMappings []PathMappingConfig `json:"statusCodePathMappings,omitempty"`
}

type TLSConfig struct {
	// CA is the path to the CA certificate file
	CA string `json:"ca,omitempty"`

	// Cert is the path to the certificate file
	Cert string `json:"cert,omitempty"`

	// Key is the path to the private key file
	Key string `json:"key,omitempty"`

	// MinVersion is the minimum TLS version to use
	MinVersion uint16 `json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version to use
	MaxVersion uint16 `json:"maxVersion,omitempty"`

	// InsecureSkipVerify indicates whether to skip certificate verification
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

type PathMappingConfig struct {
	Path     string      `json:"path,omitempty"`
	Mappings map[int]int `json:"mappings,omitempty"`
}

type ConfigParsed struct {
	Config

	Timeout time.Duration

	AuthRequestForHeader    string
	AuthRequestMethodHeader string
	AuthRequestProtoHeader  string
	AuthRequestHostHeader   string
	AuthRequestUriHeader    string

	AuthRequestAbsoluteUrlHeader string

	AuthRequestHeadersRegex  *regexp.Regexp
	AuthResponseHeadersRegex *regexp.Regexp
}

func ParseConfig(config *Config) (*ConfigParsed, error) {
	if config.Address == "" {
		return nil, fmt.Errorf("address cannot be empty")
	}

	timeout := 30 * time.Second
	if config.Timeout != "" {
		if parsedTimeout, err := time.ParseDuration(config.Timeout); err == nil {
			timeout = parsedTimeout
		} else {
			return nil, fmt.Errorf("error parsing timeout: %w", err)
		}
	}

	if config.HeaderPrefix == "" {
		config.HeaderPrefix = "X-Forwarded"
	} else if strings.HasSuffix(config.HeaderPrefix, "-") {
		config.HeaderPrefix = strings.TrimSuffix(config.HeaderPrefix, "-")

		if config.HeaderPrefix == "" {
			config.HeaderPrefix = "X-Forwarded"
		}
	}

	if config.TLS == nil {
		config.TLS = &TLSConfig{
			MinVersion:         12,
			MaxVersion:         13,
			InsecureSkipVerify: true,
		}
	} else {
		if config.TLS.MinVersion == 0 {
			config.TLS.MinVersion = 12
		} else if config.TLS.MinVersion < 10 || config.TLS.MinVersion > 13 {
			return nil, fmt.Errorf("minVersion must be between 10 and 13")
		}

		if config.TLS.MaxVersion == 0 {
			config.TLS.MaxVersion = 13
		} else if config.TLS.MaxVersion < 10 || config.TLS.MaxVersion > 13 {
			return nil, fmt.Errorf("maxVersion must be between 10 and 13")
		}

		if config.TLS.MinVersion > config.TLS.MaxVersion {
			return nil, fmt.Errorf("minVersion cannot be greater than maxVersion")
		}
	}

	// Compile auth request headers regex
	var authRequestHeadersRegex *regexp.Regexp
	if config.AuthRequestHeadersRegex != "" {
		re, err := regexp.Compile("(?i)" + config.AuthRequestHeadersRegex)
		if err != nil {
			return nil, fmt.Errorf("error compiling auth request headers regex: %w", err)
		}
		authRequestHeadersRegex = re
	}

	// Compile auth response headers regex
	var authResponseHeadersRegex *regexp.Regexp
	if config.AuthResponseHeadersRegex != "" {
		re, err := regexp.Compile("(?i)" + config.AuthResponseHeadersRegex)
		if err != nil {
			return nil, fmt.Errorf("error compiling auth response headers regex: %v", err)
		}
		authResponseHeadersRegex = re
	}

	configParsed := &ConfigParsed{
		Config: *config,

		Timeout: timeout,

		AuthRequestForHeader:    http.CanonicalHeaderKey(config.HeaderPrefix + "-For"),
		AuthRequestMethodHeader: http.CanonicalHeaderKey(config.HeaderPrefix + "-Method"),
		AuthRequestProtoHeader:  http.CanonicalHeaderKey(config.HeaderPrefix + "-Proto"),
		AuthRequestHostHeader:   http.CanonicalHeaderKey(config.HeaderPrefix + "-Host"),
		AuthRequestUriHeader:    http.CanonicalHeaderKey(config.HeaderPrefix + "-Uri"),

		AuthRequestHeadersRegex:  authRequestHeadersRegex,
		AuthResponseHeadersRegex: authResponseHeadersRegex,
	}

	if config.AbsoluteUrlHeader != "" {
		configParsed.AuthRequestAbsoluteUrlHeader = http.CanonicalHeaderKey(config.HeaderPrefix + "-" + config.AbsoluteUrlHeader)
	}

	return configParsed, nil
}
