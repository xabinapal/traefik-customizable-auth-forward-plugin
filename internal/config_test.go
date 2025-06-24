package internal_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal"
)

func TestParseConfig(t *testing.T) {
	t.Run("valid minimal config", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)
		assert.NotNil(t, parsed)

		// Check default header prefix
		assert.Equal(t, "X-Forwarded", parsed.HeaderPrefix)
		assert.Equal(t, "X-Forwarded-For", parsed.AuthRequestForHeader)
		assert.Equal(t, "X-Forwarded-Method", parsed.AuthRequestMethodHeader)
		assert.Equal(t, "X-Forwarded-Proto", parsed.AuthRequestProtoHeader)
		assert.Equal(t, "X-Forwarded-Host", parsed.AuthRequestHostHeader)
		assert.Equal(t, "X-Forwarded-Uri", parsed.AuthRequestUriHeader)
		assert.Equal(t, "", parsed.AuthRequestAbsoluteUrlHeader)

		// Check nil regex patterns
		assert.Nil(t, parsed.AuthRequestHeadersRegex)
		assert.Nil(t, parsed.AuthResponseHeadersRegex)
	})

	t.Run("custom header prefix", func(t *testing.T) {
		config := &internal.Config{
			Address:      "http://auth.example.com",
			HeaderPrefix: "X-Original",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)

		assert.Equal(t, "X-Original", parsed.HeaderPrefix)
		assert.Equal(t, "X-Original-For", parsed.AuthRequestForHeader)
		assert.Equal(t, "X-Original-Method", parsed.AuthRequestMethodHeader)
		assert.Equal(t, "X-Original-Proto", parsed.AuthRequestProtoHeader)
		assert.Equal(t, "X-Original-Host", parsed.AuthRequestHostHeader)
		assert.Equal(t, "X-Original-Uri", parsed.AuthRequestUriHeader)
	})

	t.Run("header prefix with trailing dash", func(t *testing.T) {
		config := &internal.Config{
			Address:      "http://auth.example.com",
			HeaderPrefix: "X-Custom-",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)

		assert.Equal(t, "X-Custom", parsed.HeaderPrefix)
		assert.Equal(t, "X-Custom-For", parsed.AuthRequestForHeader)
	})

	t.Run("header prefix with only dash", func(t *testing.T) {
		config := &internal.Config{
			Address:      "http://auth.example.com",
			HeaderPrefix: "-",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)

		// Should default back to X-Forwarded
		assert.Equal(t, "X-Forwarded", parsed.HeaderPrefix)
		assert.Equal(t, "X-Forwarded-For", parsed.AuthRequestForHeader)
	})

	t.Run("with absolute URL header", func(t *testing.T) {
		config := &internal.Config{
			Address:           "http://auth.example.com",
			HeaderPrefix:      "X-Custom",
			AbsoluteUrlHeader: "Url",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)

		assert.Equal(t, "X-Custom-Url", parsed.AuthRequestAbsoluteUrlHeader)
	})

	t.Run("valid auth request headers regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                 "http://auth.example.com",
			AuthRequestHeadersRegex: "^X-.*",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)
		require.NotNil(t, parsed.AuthRequestHeadersRegex)

		// Test the regex works
		assert.True(t, parsed.AuthRequestHeadersRegex.MatchString("X-Custom-Header"))
		assert.False(t, parsed.AuthRequestHeadersRegex.MatchString("Y-Other-Header"))
	})

	t.Run("case insensitive auth request regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                 "http://auth.example.com",
			AuthRequestHeadersRegex: "^authorization$",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)
		require.NotNil(t, parsed.AuthRequestHeadersRegex)

		// Should match both cases due to (?i) flag
		assert.True(t, parsed.AuthRequestHeadersRegex.MatchString("Authorization"))
		assert.True(t, parsed.AuthRequestHeadersRegex.MatchString("authorization"))
		assert.True(t, parsed.AuthRequestHeadersRegex.MatchString("AUTHORIZATION"))
	})

	t.Run("valid auth response headers regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                  "http://auth.example.com",
			AuthResponseHeadersRegex: "^X-Auth-.*",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)
		require.NotNil(t, parsed.AuthResponseHeadersRegex)

		// Test the regex works
		assert.True(t, parsed.AuthResponseHeadersRegex.MatchString("X-Auth-User"))
		assert.False(t, parsed.AuthResponseHeadersRegex.MatchString("X-Other-Header"))
	})

	t.Run("case insensitive auth response regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                  "http://auth.example.com",
			AuthResponseHeadersRegex: "^x-auth-user$",
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)
		require.NotNil(t, parsed.AuthResponseHeadersRegex)

		// Should match both cases due to (?i) flag
		assert.True(t, parsed.AuthResponseHeadersRegex.MatchString("X-Auth-User"))
		assert.True(t, parsed.AuthResponseHeadersRegex.MatchString("x-auth-user"))
		assert.True(t, parsed.AuthResponseHeadersRegex.MatchString("X-AUTH-USER"))
	})
}

func TestParseConfig_ErrorCases(t *testing.T) {
	t.Run("empty address", func(t *testing.T) {
		config := &internal.Config{
			Address: "",
		}

		parsed, err := internal.ParseConfig(config)
		assert.Error(t, err)
		assert.Nil(t, parsed)
		assert.Contains(t, err.Error(), "address cannot be empty")
	})

	t.Run("invalid auth request headers regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                 "http://auth.example.com",
			AuthRequestHeadersRegex: "[invalid-regex",
		}

		parsed, err := internal.ParseConfig(config)
		assert.Error(t, err)
		assert.Nil(t, parsed)
		assert.Contains(t, err.Error(), "error compiling auth request headers regex")
	})

	t.Run("invalid auth response headers regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                  "http://auth.example.com",
			AuthResponseHeadersRegex: "[invalid-regex",
		}

		parsed, err := internal.ParseConfig(config)
		assert.Error(t, err)
		assert.Nil(t, parsed)
		assert.Contains(t, err.Error(), "error compiling auth response headers regex")
	})
}

func TestParseConfig_ComplexRegexPatterns(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		matches    []string
		nonMatches []string
	}{
		{
			name:       "multiple alternation",
			pattern:    "^(Authorization|X-API-Key|X-Token)$",
			matches:    []string{"Authorization", "X-API-Key", "X-Token"},
			nonMatches: []string{"Content-Type", "X-Other"},
		},
		{
			name:       "prefix with dash",
			pattern:    "^X-Auth-",
			matches:    []string{"X-Auth-User", "X-Auth-Role", "X-Auth-Token"},
			nonMatches: []string{"X-Other", "Authorization"},
		},
		{
			name:       "case insensitive with word boundaries",
			pattern:    "\\bauth\\b",
			matches:    []string{"X-Auth-User", "My-Auth-Header", "auth"},
			nonMatches: []string{"authenticate", "authorization"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &internal.Config{
				Address:                 "http://auth.example.com",
				AuthRequestHeadersRegex: tt.pattern,
			}

			parsed, err := internal.ParseConfig(config)
			require.NoError(t, err)
			require.NotNil(t, parsed.AuthRequestHeadersRegex)

			for _, match := range tt.matches {
				assert.True(t, parsed.AuthRequestHeadersRegex.MatchString(match),
					"Pattern should match: %s", match)
			}

			for _, nonMatch := range tt.nonMatches {
				assert.False(t, parsed.AuthRequestHeadersRegex.MatchString(nonMatch),
					"Pattern should not match: %s", nonMatch)
			}
		})
	}
}

func TestParseConfig_FullConfiguration(t *testing.T) {
	config := &internal.Config{
		Address:                  "https://auth.example.com:8443",
		Timeout:                  60 * time.Second,
		HeaderPrefix:             "X-Custom",
		AbsoluteUrlHeader:        "Full-Url",
		TrustForwardHeader:       true,
		PreserveRequestMethod:    true,
		PreserveLocationHeader:   true,
		ForwardBody:              true,
		MaxBodySize:              1024,
		AuthRequestHeaders:       []string{"Authorization", "X-API-Key"},
		AuthRequestHeadersRegex:  "^X-Custom-.*",
		AuthRequestCookies:       []string{"session", "csrf"},
		AuthResponseHeaders:      []string{"X-User", "X-Role"},
		AuthResponseHeadersRegex: "^X-Auth-.*",
		AddAuthCookiesToResponse: []string{"token", "refresh"},
		TLS: &internal.TLSConfig{
			CA:                 "/etc/ssl/ca.pem",
			Cert:               "/etc/ssl/cert.pem",
			Key:                "/etc/ssl/key.pem",
			MinVersion:         12,
			MaxVersion:         13,
			InsecureSkipVerify: false,
		},
	}

	parsed, err := internal.ParseConfig(config)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Verify all original config is preserved
	assert.Equal(t, config.Address, parsed.Address)
	assert.Equal(t, config.Timeout, parsed.Timeout)
	assert.Equal(t, config.TrustForwardHeader, parsed.TrustForwardHeader)
	assert.Equal(t, config.PreserveRequestMethod, parsed.PreserveRequestMethod)
	assert.Equal(t, config.PreserveLocationHeader, parsed.PreserveLocationHeader)
	assert.Equal(t, config.ForwardBody, parsed.ForwardBody)
	assert.Equal(t, config.MaxBodySize, parsed.MaxBodySize)
	assert.Equal(t, config.AuthRequestHeaders, parsed.AuthRequestHeaders)
	assert.Equal(t, config.AuthRequestCookies, parsed.AuthRequestCookies)
	assert.Equal(t, config.AuthResponseHeaders, parsed.AuthResponseHeaders)
	assert.Equal(t, config.AddAuthCookiesToResponse, parsed.AddAuthCookiesToResponse)
	assert.Equal(t, config.TLS, parsed.TLS)

	// Verify computed headers
	assert.Equal(t, "X-Custom", parsed.HeaderPrefix)
	assert.Equal(t, "X-Custom-For", parsed.AuthRequestForHeader)
	assert.Equal(t, "X-Custom-Method", parsed.AuthRequestMethodHeader)
	assert.Equal(t, "X-Custom-Proto", parsed.AuthRequestProtoHeader)
	assert.Equal(t, "X-Custom-Host", parsed.AuthRequestHostHeader)
	assert.Equal(t, "X-Custom-Uri", parsed.AuthRequestUriHeader)
	assert.Equal(t, "X-Custom-Full-Url", parsed.AuthRequestAbsoluteUrlHeader)

	// Verify compiled regexes
	require.NotNil(t, parsed.AuthRequestHeadersRegex)
	require.NotNil(t, parsed.AuthResponseHeadersRegex)

	assert.True(t, parsed.AuthRequestHeadersRegex.MatchString("X-Custom-Header"))
	assert.False(t, parsed.AuthRequestHeadersRegex.MatchString("X-Other-Header"))

	assert.True(t, parsed.AuthResponseHeadersRegex.MatchString("X-Auth-User"))
	assert.False(t, parsed.AuthResponseHeadersRegex.MatchString("X-Other-User"))
}

func TestParseConfig_TLS(t *testing.T) {
	t.Run("nil TLS config uses defaults", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
			TLS:     nil,
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)
		require.NotNil(t, parsed.TLS)

		assert.Equal(t, uint16(12), parsed.TLS.MinVersion)
		assert.Equal(t, uint16(13), parsed.TLS.MaxVersion)
		assert.True(t, parsed.TLS.InsecureSkipVerify)
	})

	t.Run("partial TLS config fills in defaults", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
			TLS: &internal.TLSConfig{
				CA:   "/path/to/ca.pem",
				Cert: "/path/to/cert.pem",
				// MinVersion and MaxVersion left as zero values
			},
		}

		parsed, err := internal.ParseConfig(config)
		require.NoError(t, err)
		require.NotNil(t, parsed.TLS)

		assert.Equal(t, "/path/to/ca.pem", parsed.TLS.CA)
		assert.Equal(t, "/path/to/cert.pem", parsed.TLS.Cert)
		assert.Equal(t, uint16(12), parsed.TLS.MinVersion) // Default
		assert.Equal(t, uint16(13), parsed.TLS.MaxVersion) // Default
	})

	t.Run("TLS version validation - valid range", func(t *testing.T) {
		testCases := []struct {
			name       string
			minVersion uint16
			maxVersion uint16
		}{
			{"TLS 1.0 to 1.3", 10, 13},
			{"TLS 1.1 to 1.2", 11, 12},
			{"TLS 1.2 to 1.3", 12, 13},
			{"Same version", 12, 12},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				config := &internal.Config{
					Address: "http://auth.example.com",
					TLS: &internal.TLSConfig{
						MinVersion: tc.minVersion,
						MaxVersion: tc.maxVersion,
					},
				}

				parsed, err := internal.ParseConfig(config)
				require.NoError(t, err)
				assert.Equal(t, tc.minVersion, parsed.TLS.MinVersion)
				assert.Equal(t, tc.maxVersion, parsed.TLS.MaxVersion)
			})
		}
	})

	t.Run("TLS version validation - invalid range", func(t *testing.T) {
		testCases := []struct {
			name       string
			minVersion uint16
			maxVersion uint16
			errorMsg   string
		}{
			{"MinVersion too low", 9, 13, "minVersion must be between 10 and 13"},
			{"MinVersion too high", 14, 13, "minVersion must be between 10 and 13"},
			{"MaxVersion too low", 12, 9, "maxVersion must be between 10 and 13"},
			{"MaxVersion too high", 12, 14, "maxVersion must be between 10 and 13"},
			{"MinVersion > MaxVersion", 13, 12, "minVersion cannot be greater than maxVersion"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				config := &internal.Config{
					Address: "http://auth.example.com",
					TLS: &internal.TLSConfig{
						MinVersion: tc.minVersion,
						MaxVersion: tc.maxVersion,
					},
				}

				parsed, err := internal.ParseConfig(config)
				assert.Error(t, err)
				assert.Nil(t, parsed)
				assert.Contains(t, err.Error(), tc.errorMsg)
			})
		}
	})
}
