package internal_test

import (
	"testing"
	"time"

	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/test"
)

func TestParseConfig(t *testing.T) {
	t.Run("valid minimal config", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.AssertNotNil(t, parsed)

		// Check default header prefix
		test.AssertEqual(t, "X-Forwarded", parsed.HeaderPrefix)
		test.AssertEqual(t, "X-Forwarded-For", parsed.AuthRequestForHeader)
		test.AssertEqual(t, "X-Forwarded-Method", parsed.AuthRequestMethodHeader)
		test.AssertEqual(t, "X-Forwarded-Proto", parsed.AuthRequestProtoHeader)
		test.AssertEqual(t, "X-Forwarded-Host", parsed.AuthRequestHostHeader)
		test.AssertEqual(t, "X-Forwarded-Uri", parsed.AuthRequestUriHeader)
		test.AssertEqual(t, "", parsed.AuthRequestAbsoluteUrlHeader)

		// Check nil regex patterns
		test.AssertNil(t, parsed.AuthRequestHeadersRegex)
		test.AssertNil(t, parsed.AuthResponseHeadersRegex)
	})

	t.Run("custom header prefix", func(t *testing.T) {
		config := &internal.Config{
			Address:      "http://auth.example.com",
			HeaderPrefix: "X-Original",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)

		test.AssertEqual(t, "X-Original", parsed.HeaderPrefix)
		test.AssertEqual(t, "X-Original-For", parsed.AuthRequestForHeader)
		test.AssertEqual(t, "X-Original-Method", parsed.AuthRequestMethodHeader)
		test.AssertEqual(t, "X-Original-Proto", parsed.AuthRequestProtoHeader)
		test.AssertEqual(t, "X-Original-Host", parsed.AuthRequestHostHeader)
		test.AssertEqual(t, "X-Original-Uri", parsed.AuthRequestUriHeader)
	})

	t.Run("header prefix with trailing dash", func(t *testing.T) {
		config := &internal.Config{
			Address:      "http://auth.example.com",
			HeaderPrefix: "X-Custom-",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)

		test.AssertEqual(t, "X-Custom", parsed.HeaderPrefix)
		test.AssertEqual(t, "X-Custom-For", parsed.AuthRequestForHeader)
	})

	t.Run("header prefix with only dash", func(t *testing.T) {
		config := &internal.Config{
			Address:      "http://auth.example.com",
			HeaderPrefix: "-",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)

		// Should default back to X-Forwarded
		test.AssertEqual(t, "X-Forwarded", parsed.HeaderPrefix)
		test.AssertEqual(t, "X-Forwarded-For", parsed.AuthRequestForHeader)
	})

	t.Run("with absolute URL header", func(t *testing.T) {
		config := &internal.Config{
			Address:           "http://auth.example.com",
			HeaderPrefix:      "X-Custom",
			AbsoluteUrlHeader: "Url",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)

		test.AssertEqual(t, "X-Custom-Url", parsed.AuthRequestAbsoluteUrlHeader)
	})

	t.Run("valid auth request headers regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                 "http://auth.example.com",
			AuthRequestHeadersRegex: "^X-.*",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed.AuthRequestHeadersRegex)

		// Test the regex works
		test.AssertTrue(t, parsed.AuthRequestHeadersRegex.MatchString("X-Custom-Header"))
		test.AssertFalse(t, parsed.AuthRequestHeadersRegex.MatchString("Y-Other-Header"))
	})

	t.Run("case insensitive auth request regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                 "http://auth.example.com",
			AuthRequestHeadersRegex: "^authorization$",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed.AuthRequestHeadersRegex)

		// Should match both cases due to (?i) flag
		test.AssertTrue(t, parsed.AuthRequestHeadersRegex.MatchString("Authorization"))
		test.AssertTrue(t, parsed.AuthRequestHeadersRegex.MatchString("authorization"))
		test.AssertTrue(t, parsed.AuthRequestHeadersRegex.MatchString("AUTHORIZATION"))
	})

	t.Run("valid auth response headers regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                  "http://auth.example.com",
			AuthResponseHeadersRegex: "^X-Auth-.*",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed.AuthResponseHeadersRegex)

		// Test the regex works
		test.AssertTrue(t, parsed.AuthResponseHeadersRegex.MatchString("X-Auth-User"))
		test.AssertFalse(t, parsed.AuthResponseHeadersRegex.MatchString("X-Other-Header"))
	})

	t.Run("case insensitive auth response regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                  "http://auth.example.com",
			AuthResponseHeadersRegex: "^x-auth-user$",
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed.AuthResponseHeadersRegex)

		// Should match both cases due to (?i) flag
		test.AssertTrue(t, parsed.AuthResponseHeadersRegex.MatchString("X-Auth-User"))
		test.AssertTrue(t, parsed.AuthResponseHeadersRegex.MatchString("x-auth-user"))
		test.AssertTrue(t, parsed.AuthResponseHeadersRegex.MatchString("X-AUTH-USER"))
	})
}

func TestParseConfig_ErrorCases(t *testing.T) {
	t.Run("empty address", func(t *testing.T) {
		config := &internal.Config{
			Address: "",
		}

		parsed, err := internal.ParseConfig(config)
		test.AssertError(t, err)
		test.AssertNil(t, parsed)
		test.AssertContains(t, err.Error(), "address cannot be empty")
	})

	t.Run("invalid auth request headers regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                 "http://auth.example.com",
			AuthRequestHeadersRegex: "[invalid-regex",
		}

		parsed, err := internal.ParseConfig(config)
		test.AssertError(t, err)
		test.AssertNil(t, parsed)
		test.AssertContains(t, err.Error(), "error compiling auth request headers regex")
	})

	t.Run("invalid auth response headers regex", func(t *testing.T) {
		config := &internal.Config{
			Address:                  "http://auth.example.com",
			AuthResponseHeadersRegex: "[invalid-regex",
		}

		parsed, err := internal.ParseConfig(config)
		test.AssertError(t, err)
		test.AssertNil(t, parsed)
		test.AssertContains(t, err.Error(), "error compiling auth response headers regex")
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
			test.RequireNoError(t, err)
			test.RequireNotNil(t, parsed.AuthRequestHeadersRegex)

			for _, match := range tt.matches {
				test.AssertTrue(t, parsed.AuthRequestHeadersRegex.MatchString(match),
					"Pattern should match: %s", match)
			}

			for _, nonMatch := range tt.nonMatches {
				test.AssertFalse(t, parsed.AuthRequestHeadersRegex.MatchString(nonMatch),
					"Pattern should not match: %s", nonMatch)
			}
		})
	}
}

func TestParseConfig_FullConfiguration(t *testing.T) {
	config := &internal.Config{
		Address:                  "https://auth.example.com:8443",
		Timeout:                  "60s",
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
		StatusCodeGlobalMappings: map[int]int{
			401: 403,
			404: 410,
		},
		StatusCodePathMappings: []internal.PathMappingConfig{
			{
				Path: "/api",
				Mappings: map[int]int{
					401: 418,
					500: 502,
				},
			},
		},
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
	test.RequireNoError(t, err)
	test.RequireNotNil(t, parsed)

	parsedTimeout, err := time.ParseDuration(config.Timeout)
	test.RequireNoError(t, err)

	// Verify all original config is preserved
	test.AssertEqual(t, config.Address, parsed.Address)
	test.AssertEqual(t, parsedTimeout, parsed.Timeout)
	test.AssertEqual(t, config.TrustForwardHeader, parsed.TrustForwardHeader)
	test.AssertEqual(t, config.PreserveRequestMethod, parsed.PreserveRequestMethod)
	test.AssertEqual(t, config.PreserveLocationHeader, parsed.PreserveLocationHeader)
	test.AssertEqual(t, config.ForwardBody, parsed.ForwardBody)
	test.AssertEqual(t, config.MaxBodySize, parsed.MaxBodySize)
	test.AssertEqual(t, config.AuthRequestHeaders, parsed.AuthRequestHeaders)
	test.AssertEqual(t, config.AuthRequestCookies, parsed.AuthRequestCookies)
	test.AssertEqual(t, config.AuthResponseHeaders, parsed.AuthResponseHeaders)
	test.AssertEqual(t, config.AddAuthCookiesToResponse, parsed.AddAuthCookiesToResponse)
	test.AssertEqual(t, config.StatusCodeGlobalMappings, parsed.StatusCodeGlobalMappings)
	test.AssertEqual(t, config.StatusCodePathMappings, parsed.StatusCodePathMappings)
	test.AssertEqual(t, config.TLS, parsed.TLS)

	// Verify computed headers
	test.AssertEqual(t, "X-Custom", parsed.HeaderPrefix)
	test.AssertEqual(t, "X-Custom-For", parsed.AuthRequestForHeader)
	test.AssertEqual(t, "X-Custom-Method", parsed.AuthRequestMethodHeader)
	test.AssertEqual(t, "X-Custom-Proto", parsed.AuthRequestProtoHeader)
	test.AssertEqual(t, "X-Custom-Host", parsed.AuthRequestHostHeader)
	test.AssertEqual(t, "X-Custom-Uri", parsed.AuthRequestUriHeader)
	test.AssertEqual(t, "X-Custom-Full-Url", parsed.AuthRequestAbsoluteUrlHeader)

	// Verify compiled regexes
	test.RequireNotNil(t, parsed.AuthRequestHeadersRegex)
	test.RequireNotNil(t, parsed.AuthResponseHeadersRegex)

	test.AssertTrue(t, parsed.AuthRequestHeadersRegex.MatchString("X-Custom-Header"))
	test.AssertFalse(t, parsed.AuthRequestHeadersRegex.MatchString("X-Other-Header"))

	test.AssertTrue(t, parsed.AuthResponseHeadersRegex.MatchString("X-Auth-User"))
	test.AssertFalse(t, parsed.AuthResponseHeadersRegex.MatchString("X-Other-User"))
}

func TestParseConfig_TLS(t *testing.T) {
	t.Run("nil TLS config uses defaults", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
			TLS:     nil,
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed.TLS)

		test.AssertEqual(t, uint16(12), parsed.TLS.MinVersion)
		test.AssertEqual(t, uint16(13), parsed.TLS.MaxVersion)
		test.AssertTrue(t, parsed.TLS.InsecureSkipVerify)
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
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed.TLS)

		test.AssertEqual(t, "/path/to/ca.pem", parsed.TLS.CA)
		test.AssertEqual(t, "/path/to/cert.pem", parsed.TLS.Cert)
		test.AssertEqual(t, uint16(12), parsed.TLS.MinVersion) // Default
		test.AssertEqual(t, uint16(13), parsed.TLS.MaxVersion) // Default
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
				test.RequireNoError(t, err)
				test.AssertEqual(t, tc.minVersion, parsed.TLS.MinVersion)
				test.AssertEqual(t, tc.maxVersion, parsed.TLS.MaxVersion)
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
				test.AssertError(t, err)
				test.AssertNil(t, parsed)
				test.AssertContains(t, err.Error(), tc.errorMsg)
			})
		}
	})
}

func TestParseConfig_StatusCodeMappings(t *testing.T) {
	t.Run("global status code mappings are preserved", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
			StatusCodeGlobalMappings: map[int]int{
				401: 403,
				404: 401,
				500: 502,
			},
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed)

		test.AssertEqual(t, config.StatusCodeGlobalMappings, parsed.StatusCodeGlobalMappings)
		test.AssertEqual(t, 403, parsed.StatusCodeGlobalMappings[401])
		test.AssertEqual(t, 401, parsed.StatusCodeGlobalMappings[404])
		test.AssertEqual(t, 502, parsed.StatusCodeGlobalMappings[500])
	})

	t.Run("path status code mappings are preserved", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
			StatusCodePathMappings: []internal.PathMappingConfig{
				{
					Path: "/api",
					Mappings: map[int]int{
						401: 403,
						404: 410,
					},
				},
				{
					Path: "/admin",
					Mappings: map[int]int{
						401: 404,
						403: 404,
					},
				},
			},
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed)

		test.AssertEqual(t, len(config.StatusCodePathMappings), len(parsed.StatusCodePathMappings))

		// Verify first mapping
		test.AssertEqual(t, "/api", parsed.StatusCodePathMappings[0].Path)
		test.AssertEqual(t, 403, parsed.StatusCodePathMappings[0].Mappings[401])
		test.AssertEqual(t, 410, parsed.StatusCodePathMappings[0].Mappings[404])

		// Verify second mapping
		test.AssertEqual(t, "/admin", parsed.StatusCodePathMappings[1].Path)
		test.AssertEqual(t, 404, parsed.StatusCodePathMappings[1].Mappings[401])
		test.AssertEqual(t, 404, parsed.StatusCodePathMappings[1].Mappings[403])
	})

	t.Run("empty status code mappings are preserved", func(t *testing.T) {
		config := &internal.Config{
			Address:                  "http://auth.example.com",
			StatusCodeGlobalMappings: map[int]int{},
			StatusCodePathMappings:   []internal.PathMappingConfig{},
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed)

		test.AssertNotNil(t, parsed.StatusCodeGlobalMappings)
		test.AssertNotNil(t, parsed.StatusCodePathMappings)
		test.AssertEmpty(t, parsed.StatusCodeGlobalMappings)
		test.AssertEmpty(t, parsed.StatusCodePathMappings)
	})

	t.Run("nil status code mappings are handled", func(t *testing.T) {
		config := &internal.Config{
			Address:                  "http://auth.example.com",
			StatusCodeGlobalMappings: nil,
			StatusCodePathMappings:   nil,
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed)

		// Should be nil (not converted to empty map/slice)
		test.AssertNil(t, parsed.StatusCodeGlobalMappings)
		test.AssertNil(t, parsed.StatusCodePathMappings)
	})

	t.Run("complex status code mappings configuration", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
			StatusCodeGlobalMappings: map[int]int{
				401: 403,
				404: 410,
				500: 502,
				503: 504,
			},
			StatusCodePathMappings: []internal.PathMappingConfig{
				{
					Path: "/api/v1",
					Mappings: map[int]int{
						401: 418, // I'm a teapot
						403: 451, // Unavailable for legal reasons
					},
				},
				{
					Path: "/api/v2",
					Mappings: map[int]int{
						401: 429, // Too many requests
						404: 406, // Not acceptable
						500: 507, // Insufficient storage
					},
				},
				{
					Path: "/admin",
					Mappings: map[int]int{
						401: 404, // Hide admin existence
						403: 404,
						500: 404,
					},
				},
			},
		}

		parsed, err := internal.ParseConfig(config)
		test.RequireNoError(t, err)
		test.RequireNotNil(t, parsed)

		// Verify global mappings
		test.AssertEqual(t, 4, len(parsed.StatusCodeGlobalMappings))
		test.AssertEqual(t, 403, parsed.StatusCodeGlobalMappings[401])
		test.AssertEqual(t, 410, parsed.StatusCodeGlobalMappings[404])
		test.AssertEqual(t, 502, parsed.StatusCodeGlobalMappings[500])
		test.AssertEqual(t, 504, parsed.StatusCodeGlobalMappings[503])

		// Verify path mappings count
		test.AssertEqual(t, 3, len(parsed.StatusCodePathMappings))

		// Verify /api/v1 mappings
		apiV1 := parsed.StatusCodePathMappings[0]
		test.AssertEqual(t, "/api/v1", apiV1.Path)
		test.AssertEqual(t, 2, len(apiV1.Mappings))
		test.AssertEqual(t, 418, apiV1.Mappings[401])
		test.AssertEqual(t, 451, apiV1.Mappings[403])

		// Verify /api/v2 mappings
		apiV2 := parsed.StatusCodePathMappings[1]
		test.AssertEqual(t, "/api/v2", apiV2.Path)
		test.AssertEqual(t, 3, len(apiV2.Mappings))
		test.AssertEqual(t, 429, apiV2.Mappings[401])
		test.AssertEqual(t, 406, apiV2.Mappings[404])
		test.AssertEqual(t, 507, apiV2.Mappings[500])

		// Verify /admin mappings
		admin := parsed.StatusCodePathMappings[2]
		test.AssertEqual(t, "/admin", admin.Path)
		test.AssertEqual(t, 3, len(admin.Mappings))
		test.AssertEqual(t, 404, admin.Mappings[401])
		test.AssertEqual(t, 404, admin.Mappings[403])
		test.AssertEqual(t, 404, admin.Mappings[500])
	})
}
