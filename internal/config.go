package internal

import "time"

type Config struct {
	// Address is the URL of the authentication service
	Address string `json:"address,omitempty"`

	// Timeout for auth service requests
	Timeout time.Duration `json:"timeout,omitempty"`

	// TLS configuration for secure connection to auth service
	TLS *TLSConfig `json:"tls,omitempty"`

	// HeaderPrefix allows customization of the forwarded header names
	// Default is "X-Forwarded" which results in standard headers like "X-Forwarded-Host"
	// Setting this to "X-Original" would result in "X-Original-Host", etc.
	HeaderPrefix string `json:"headerPrefix,omitempty"`

	// TrustForwardHeader indicates whether to trust existing forward headers
	TrustForwardHeader bool `json:"trustForwardHeader,omitempty"`

	// AuthRequestHeaders is a list of headers to copy from original request to auth request
	AuthRequestHeaders []string `json:"authRequestHeaders,omitempty"`

	// AddAuthCookiesToResponse is a list of cookie names to copy from auth response
	AddAuthCookiesToResponse []string `json:"addAuthCookiesToResponse,omitempty"`

	// AuthResponseHeaders is a list of headers to copy from auth response to the forwarded request
	AuthResponseHeaders []string `json:"authResponseHeaders,omitempty"`

	// AuthResponseHeadersRegex is a regex pattern to match headers to copy from auth response
	AuthResponseHeadersRegex string `json:"authResponseHeadersRegex,omitempty"`

	// ForwardBody indicates whether to forward the request body to the auth service
	ForwardBody bool `json:"forwardBody,omitempty"`

	// MaxBodySize sets the maximum size of the body to forward (default: 64KB)
	MaxBodySize int64 `json:"maxBodySize,omitempty"`

	// HeaderField specifies which header field to use for storing authenticated user info
	HeaderField string `json:"headerField,omitempty"`

	// PreserveRequestMethod indicates whether to preserve the original request method
	PreserveRequestMethod bool `json:"preserveRequestMethod,omitempty"`

	// PreserveLocationHeader indicates whether to preserve the Location header from auth response
	PreserveLocationHeader bool `json:"preserveLocationHeader,omitempty"`
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
