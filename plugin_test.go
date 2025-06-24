package traefik_customizable_auth_forward_plugin_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	plugin "github.com/xabinapal/traefik-customizable-auth-forward-plugin"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/test"
)

func TestCreateConfig(t *testing.T) {
	config := plugin.CreateConfig()

	// Verify all default values are set correctly
	test.AssertEqual(t, "", config.Address)
	test.AssertEqual(t, "30s", config.Timeout)
	test.AssertEqual(t, "X-Forwarded", config.HeaderPrefix)
	test.AssertFalse(t, config.PreserveRequestMethod)
	test.AssertFalse(t, config.TrustForwardHeader)
	test.AssertFalse(t, config.PreserveLocationHeader)
	test.AssertFalse(t, config.ForwardBody)
	test.AssertEqual(t, int64(-1), config.MaxBodySize)

	// Verify TLS defaults
	test.RequireNotNil(t, config.TLS)
	test.AssertEqual(t, "", config.TLS.CA)
	test.AssertEqual(t, "", config.TLS.Cert)
	test.AssertEqual(t, "", config.TLS.Key)
	test.AssertFalse(t, config.TLS.InsecureSkipVerify)

	// Verify slice fields are initialized
	test.AssertNotNil(t, config.AuthRequestHeaders)
	test.AssertNotNil(t, config.AuthRequestCookies)
	test.AssertNotNil(t, config.AuthResponseHeaders)
	test.AssertNotNil(t, config.AddAuthCookiesToResponse)
	test.AssertEmpty(t, config.AuthRequestHeaders)
	test.AssertEmpty(t, config.AuthRequestCookies)
	test.AssertEmpty(t, config.AuthResponseHeaders)
	test.AssertEmpty(t, config.AddAuthCookiesToResponse)

	// Verify status code mapping defaults
	test.AssertNotNil(t, config.StatusCodeGlobalMappings)
	test.AssertNotNil(t, config.StatusCodePathMappings)
	test.AssertEmpty(t, config.StatusCodeGlobalMappings)
	test.AssertEmpty(t, config.StatusCodePathMappings)
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("successful creation", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
			Timeout: "10s",
		}

		handler, err := plugin.New(ctx, next, config, "test-plugin")
		test.RequireNoError(t, err)
		test.AssertNotNil(t, handler)
	})

	t.Run("empty address returns error", func(t *testing.T) {
		config := &internal.Config{
			Address: "",
			Timeout: "10s",
		}

		handler, err := plugin.New(ctx, next, config, "test-plugin")
		test.AssertError(t, err)
		test.AssertNil(t, handler)
		test.AssertContains(t, err.Error(), "address cannot be empty")
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		config := &internal.Config{
			Address:                 "http://auth.example.com",
			AuthRequestHeadersRegex: "[invalid-regex",
		}

		handler, err := plugin.New(ctx, next, config, "test-plugin")
		test.AssertError(t, err)
		test.AssertNil(t, handler)
		test.AssertContains(t, err.Error(), "error parsing config")
	})
}

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		name            string
		authStatusCode  int
		authHeaders     map[string]string
		authBody        string
		config          func() *internal.Config
		expectedStatus  int
		expectedBody    string
		expectedHeaders map[string]string
		setupRequest    func(*http.Request)
		validateNext    func(t *testing.T, req *http.Request)
	}{
		{
			name:           "successful auth with headers forwarded",
			authStatusCode: http.StatusOK,
			authHeaders: map[string]string{
				"X-Auth-User":  "john.doe",
				"X-Auth-Email": "john@example.com",
			},
			authBody: "OK",
			config: func() *internal.Config {
				config := plugin.CreateConfig()
				config.Address = "PLACEHOLDER"
				config.AuthResponseHeaders = []string{"X-Auth-User", "X-Auth-Email"}
				return config
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Success from next handler",
			validateNext: func(t *testing.T, req *http.Request) {
				t.Helper()
				test.AssertEqual(t, "john.doe", req.Header.Get("X-Auth-User"))
				test.AssertEqual(t, "john@example.com", req.Header.Get("X-Auth-Email"))
			},
		},
		{
			name:           "auth service returns 401 - forwarded to client",
			authStatusCode: http.StatusUnauthorized,
			authHeaders: map[string]string{
				"WWW-Authenticate": "Bearer",
			},
			authBody: "Unauthorized",
			config: func() *internal.Config {
				config := plugin.CreateConfig()
				config.Address = "PLACEHOLDER"
				return config
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Unauthorized",
			validateNext: func(t *testing.T, req *http.Request) {
				t.Error("next handler should not be called for non-2xx auth response")
			},
		},
		{
			name:           "auth service returns 302 with location header",
			authStatusCode: http.StatusFound,
			authHeaders: map[string]string{
				"Location": "/login",
			},
			authBody: "Found",
			config: func() *internal.Config {
				config := plugin.CreateConfig()
				config.Address = "PLACEHOLDER"
				return config
			},
			expectedStatus: http.StatusFound,
			expectedBody:   "Found",
			expectedHeaders: map[string]string{
				"Location": "/login",
			},
			validateNext: func(t *testing.T, req *http.Request) {
				t.Error("next handler should not be called for non-2xx auth response")
			},
		},
		{
			name:           "auth service returns 302 with relative location and preserve enabled",
			authStatusCode: http.StatusFound,
			authHeaders: map[string]string{
				"Location": "/login",
			},
			authBody: "Found",
			config: func() *internal.Config {
				config := plugin.CreateConfig()
				config.Address = "PLACEHOLDER"
				config.PreserveLocationHeader = true
				return config
			},
			expectedStatus: http.StatusFound,
			expectedBody:   "Found",
			expectedHeaders: map[string]string{
				"Location": "DYNAMIC", // Will be checked dynamically since server URL is dynamic
			},
			validateNext: func(t *testing.T, req *http.Request) {
				t.Error("next handler should not be called for non-2xx auth response")
			},
		},
		{
			name:           "auth service returns 302 with absolute location and preserve enabled",
			authStatusCode: http.StatusFound,
			authHeaders: map[string]string{
				"Location": "https://external.example.com/login",
			},
			authBody: "Found",
			config: func() *internal.Config {
				config := plugin.CreateConfig()
				config.Address = "PLACEHOLDER"
				config.PreserveLocationHeader = true
				return config
			},
			expectedStatus: http.StatusFound,
			expectedBody:   "Found",
			expectedHeaders: map[string]string{
				"Location": "https://external.example.com/login",
			},
			validateNext: func(t *testing.T, req *http.Request) {
				t.Error("next handler should not be called for non-2xx auth response")
			},
		},
		{
			name:           "auth with regex header matching",
			authStatusCode: http.StatusOK,
			authHeaders: map[string]string{
				"X-Custom-Header": "custom-value",
				"X-Other-Header":  "other-value",
				"Y-Skip-Header":   "skip-value",
			},
			authBody: "OK",
			config: func() *internal.Config {
				config := plugin.CreateConfig()
				config.Address = "PLACEHOLDER"
				config.AuthResponseHeadersRegex = "^X-.*"
				return config
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Success from next handler",
			validateNext: func(t *testing.T, req *http.Request) {
				t.Helper()
				test.AssertEqual(t, "custom-value", req.Header.Get("X-Custom-Header"))
				test.AssertEqual(t, "other-value", req.Header.Get("X-Other-Header"))
				test.AssertEqual(t, "", req.Header.Get("Y-Skip-Header"))
			},
		},
		{
			name:           "auth with cookies forwarded",
			authStatusCode: http.StatusOK,
			authHeaders:    map[string]string{},
			authBody:       "OK",
			config: func() *internal.Config {
				config := plugin.CreateConfig()
				config.Address = "PLACEHOLDER"
				config.AddAuthCookiesToResponse = []string{"session", "user"}
				return config
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "Success from next handler",
			validateNext: func(t *testing.T, req *http.Request) {
				t.Helper()
				cookies := req.Cookies()
				sessionFound := false
				userFound := false
				for _, cookie := range cookies {
					if cookie.Name == "session" && cookie.Value == "abc123" {
						sessionFound = true
					}
					if cookie.Name == "user" && cookie.Value == "john" {
						userFound = true
					}
				}
				test.AssertTrue(t, sessionFound, "session cookie should be forwarded")
				test.AssertTrue(t, userFound, "user cookie should be forwarded")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create auth server
			authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Set response headers
				for key, value := range tt.authHeaders {
					w.Header().Set(key, value)
				}

				// Set cookies for cookie test
				if tt.name == "auth with cookies forwarded" {
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
					http.SetCookie(w, &http.Cookie{Name: "user", Value: "john"})
					http.SetCookie(w, &http.Cookie{Name: "other", Value: "skip"})
				}

				w.WriteHeader(tt.authStatusCode)
				_, _ = w.Write([]byte(tt.authBody))
			}))
			defer authServer.Close()

			// Setup config
			config := tt.config()
			config.Address = authServer.URL

			// Create next handler
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				if tt.validateNext != nil {
					tt.validateNext(t, r)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Success from next handler"))
			})

			// Create plugin
			handler, err := plugin.New(context.Background(), next, config, "test-plugin")
			test.RequireNoError(t, err)

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
			if tt.setupRequest != nil {
				tt.setupRequest(req)
			}
			recorder := httptest.NewRecorder()

			// Execute
			handler.ServeHTTP(recorder, req)

			// Verify response
			test.AssertEqual(t, tt.expectedStatus, recorder.Code)
			test.AssertEqual(t, tt.expectedBody, recorder.Body.String())

			// Verify headers
			for key, value := range tt.expectedHeaders {
				if value == "DYNAMIC" && key == "Location" {
					// For dynamic location header, just check it contains /login
					location := recorder.Header().Get("Location")
					test.AssertContains(t, location, "/login", "Location header should contain /login")
				} else {
					test.AssertEqual(t, value, recorder.Header().Get(key))
				}
			}

			// Verify next handler was called appropriately
			if tt.expectedStatus >= http.StatusOK && tt.expectedStatus < http.StatusMultipleChoices {
				test.AssertTrue(t, nextCalled, "next handler should be called for 2xx auth response")
			} else {
				test.AssertFalse(t, nextCalled, "next handler should not be called for non-2xx auth response")
			}
		})
	}
}

func TestServeHTTP_ErrorScenarios(t *testing.T) {
	t.Run("auth service unreachable", func(t *testing.T) {
		config := plugin.CreateConfig()
		config.Address = "http://nonexistent.example.com:99999"

		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("next handler should not be called when auth service is unreachable")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		test.RequireNoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		test.AssertEqual(t, http.StatusInternalServerError, recorder.Code)
		test.AssertContains(t, recorder.Body.String(), "dial tcp")
	})

	t.Run("malformed auth service URL", func(t *testing.T) {
		config := plugin.CreateConfig()
		config.Address = "://invalid-url"

		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("next handler should not be called with invalid auth URL")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		test.RequireNoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		test.AssertEqual(t, http.StatusInternalServerError, recorder.Code)
		test.AssertContains(t, recorder.Body.String(), "error creating auth request")
	})

	t.Run("auth service returns invalid location header", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "://invalid-location")
			w.WriteHeader(http.StatusFound)
			_, _ = w.Write([]byte("Found"))
		}))
		defer authServer.Close()

		config := plugin.CreateConfig()
		config.Address = authServer.URL
		config.PreserveLocationHeader = true

		next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("next handler should not be called for redirect response")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		test.RequireNoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		// Should return 500 error when location parsing fails
		test.AssertEqual(t, http.StatusInternalServerError, recorder.Code)
	})
}

func TestServeHTTP_RequestHeaders(t *testing.T) {
	tests := []struct {
		name            string
		headerPrefix    string
		expectedHeaders map[string]string
	}{
		{
			name:         "default header prefix",
			headerPrefix: "X-Forwarded",
			expectedHeaders: map[string]string{
				"X-Forwarded-Host":   "example.com",
				"X-Forwarded-Proto":  "http",
				"X-Forwarded-Method": http.MethodGet,
				"X-Forwarded-Uri":    "http://example.com/test", // Request.RequestURI is full URL
			},
		},
		{
			name:         "custom header prefix",
			headerPrefix: "X-Original",
			expectedHeaders: map[string]string{
				"X-Original-Host":   "example.com",
				"X-Original-Proto":  "http",
				"X-Original-Method": http.MethodGet,
				"X-Original-Uri":    "http://example.com/test", // Request.RequestURI is full URL
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create auth server that captures request headers
			var capturedHeaders http.Header
			authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedHeaders = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			}))
			defer authServer.Close()

			config := plugin.CreateConfig()
			config.Address = authServer.URL
			config.HeaderPrefix = tt.headerPrefix

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler, err := plugin.New(context.Background(), next, config, "test-plugin")
			test.RequireNoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)

			// Verify auth request headers
			for key, value := range tt.expectedHeaders {
				test.AssertEqual(t, value, capturedHeaders.Get(key), "header %s should be set correctly", key)
			}
		})
	}
}

func TestServeHTTP_BodyForwarding(t *testing.T) {
	tests := []struct {
		name          string
		forwardBody   bool
		maxBodySize   int64
		requestBody   string
		expectedError bool
		description   string
	}{
		{
			name:        "body forwarding disabled",
			forwardBody: false,
			requestBody: "test body",
			description: "should not forward body when disabled",
		},
		{
			name:        "body forwarding enabled",
			forwardBody: true,
			requestBody: "test body",
			description: "should forward body when enabled",
		},
		{
			name:        "body forwarding with size limit",
			forwardBody: true,
			maxBodySize: 5,
			requestBody: "this is a long body that should be truncated",
			description: "should truncate body when max size is set",
		},
		{
			name:        "empty body with forwarding enabled",
			forwardBody: true,
			requestBody: "",
			description: "should handle empty body gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedBody []byte

			// Create auth server that captures the request body
			authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Body != nil {
					body, _ := io.ReadAll(r.Body)
					receivedBody = body
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			}))
			defer authServer.Close()

			config := plugin.CreateConfig()
			config.Address = authServer.URL
			config.ForwardBody = tt.forwardBody
			config.MaxBodySize = tt.maxBodySize

			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Success from next handler"))
			})

			handler, err := plugin.New(context.Background(), next, config, "test-plugin")
			test.RequireNoError(t, err)

			var req *http.Request
			if tt.requestBody != "" {
				req = httptest.NewRequest(http.MethodPost, "http://example.com/test", strings.NewReader(tt.requestBody))
			} else {
				req = httptest.NewRequest(http.MethodPost, "http://example.com/test", nil)
			}
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)

			if tt.forwardBody && tt.requestBody != "" {
				if tt.maxBodySize > 0 && int64(len(tt.requestBody)) > tt.maxBodySize {
					expectedTruncated := tt.requestBody[:tt.maxBodySize]
					if len(receivedBody) > 0 {
						test.AssertEqual(t, expectedTruncated, string(receivedBody), "Body should be truncated to max size")
					}
				} else {
					if len(receivedBody) > 0 {
						test.AssertEqual(t, tt.requestBody, string(receivedBody), "Body should be forwarded completely")
					}
				}
			} else if !tt.forwardBody {
				// When body forwarding is disabled, auth request should have no body or empty body
				test.AssertEmpty(t, receivedBody, "Body should not be forwarded when disabled")
			}

			test.AssertEqual(t, http.StatusOK, recorder.Code)
		})
	}
}

func TestServeHTTP_TimeoutScenarios(t *testing.T) {
	t.Run("auth service timeout", func(t *testing.T) {
		// Create a slow auth server
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond) // Longer than our timeout
			w.WriteHeader(http.StatusOK)
		}))
		defer authServer.Close()

		config := plugin.CreateConfig()
		config.Address = authServer.URL
		config.Timeout = "50ms"

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called on timeout")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		test.RequireNoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		test.AssertEqual(t, http.StatusInternalServerError, recorder.Code)
		test.AssertContains(t, recorder.Body.String(), "context deadline exceeded")
	})
}

func TestServeHTTP_AdvancedHeaderScenarios(t *testing.T) {
	t.Run("trust forward header scenarios", func(t *testing.T) {
		tests := []struct {
			name               string
			trustForwardHeader bool
			existingHeaders    map[string]string
			expectedForwarded  map[string]string
		}{
			{
				name:               "trust existing forward headers",
				trustForwardHeader: true,
				existingHeaders: map[string]string{
					"X-Forwarded-For":    "203.0.113.1",
					"X-Forwarded-Proto":  "https",
					"X-Forwarded-Host":   "trusted.example.com",
					"X-Forwarded-Method": "PUT",
					"X-Forwarded-Uri":    "/trusted/path",
				},
				expectedForwarded: map[string]string{
					"X-Forwarded-For":    "203.0.113.1",
					"X-Forwarded-Proto":  "https",
					"X-Forwarded-Host":   "trusted.example.com",
					"X-Forwarded-Method": "PUT",
					"X-Forwarded-Uri":    "/trusted/path",
				},
			},
			{
				name:               "ignore existing forward headers when not trusted",
				trustForwardHeader: false,
				existingHeaders: map[string]string{
					"X-Forwarded-For":   "203.0.113.1",
					"X-Forwarded-Proto": "https",
					"X-Forwarded-Host":  "untrusted.example.com",
				},
				expectedForwarded: map[string]string{
					"X-Forwarded-Proto":  "http", // Determined from request
					"X-Forwarded-Host":   "example.com",
					"X-Forwarded-Method": http.MethodGet,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var capturedHeaders http.Header

				authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					capturedHeaders = r.Header.Clone()
					w.WriteHeader(http.StatusOK)
				}))
				defer authServer.Close()

				config := plugin.CreateConfig()
				config.Address = authServer.URL
				config.TrustForwardHeader = tt.trustForwardHeader

				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})

				handler, err := plugin.New(context.Background(), next, config, "test-plugin")
				test.RequireNoError(t, err)

				req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
				req.RemoteAddr = "192.168.1.100:12345"

				// Set existing forward headers
				for key, value := range tt.existingHeaders {
					req.Header.Set(key, value)
				}

				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, req)

				// Verify expected headers were forwarded to auth service
				if tt.trustForwardHeader {
					// When trusting, should use the provided forward headers
					for key, expectedValue := range tt.expectedForwarded {
						actualValue := capturedHeaders.Get(key)
						test.AssertEqual(t, expectedValue, actualValue, "Header %s should match expected value", key)
					}
				} else {
					// When not trusting, should generate new headers from request
					test.AssertEqual(t, "192.168.1.100", capturedHeaders.Get("X-Forwarded-For"))
					test.AssertEqual(t, "http", capturedHeaders.Get("X-Forwarded-Proto"))
					test.AssertEqual(t, "example.com", capturedHeaders.Get("X-Forwarded-Host"))
					test.AssertEqual(t, http.MethodGet, capturedHeaders.Get("X-Forwarded-Method"))
				}
			})
		}
	})
}

func TestServeHTTP_StatusCodeMapping(t *testing.T) {
	t.Run("global status code mapping", func(t *testing.T) {
		tests := []struct {
			name               string
			authStatusCode     int
			globalMappings     map[int]int
			expectedStatusCode int
		}{
			{
				name:           "401 mapped to 403",
				authStatusCode: http.StatusUnauthorized,
				globalMappings: map[int]int{
					http.StatusUnauthorized: http.StatusForbidden,
				},
				expectedStatusCode: http.StatusForbidden,
			},
			{
				name:           "404 mapped to 401",
				authStatusCode: http.StatusNotFound,
				globalMappings: map[int]int{
					http.StatusNotFound: http.StatusUnauthorized,
				},
				expectedStatusCode: http.StatusUnauthorized,
			},
			{
				name:           "unmapped status code remains unchanged",
				authStatusCode: http.StatusBadRequest,
				globalMappings: map[int]int{
					http.StatusUnauthorized: http.StatusForbidden,
				},
				expectedStatusCode: http.StatusBadRequest,
			},
			{
				name:           "multiple mappings - correct one applied",
				authStatusCode: http.StatusNotFound,
				globalMappings: map[int]int{
					http.StatusUnauthorized: http.StatusForbidden,
					http.StatusNotFound:     http.StatusGone,
					http.StatusBadRequest:   http.StatusTooManyRequests,
				},
				expectedStatusCode: http.StatusGone,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Create auth server that returns the specified status code
				authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.authStatusCode)
					_, _ = w.Write([]byte("Auth response"))
				}))
				defer authServer.Close()

				config := plugin.CreateConfig()
				config.Address = authServer.URL
				config.StatusCodeGlobalMappings = tt.globalMappings

				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("next handler should not be called for non-2xx auth response")
				})

				handler, err := plugin.New(context.Background(), next, config, "test-plugin")
				test.RequireNoError(t, err)

				req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
				recorder := httptest.NewRecorder()

				handler.ServeHTTP(recorder, req)

				test.AssertEqual(t, tt.expectedStatusCode, recorder.Code)
				test.AssertEqual(t, "Auth response", recorder.Body.String())
			})
		}
	})

	t.Run("path-based status code mapping", func(t *testing.T) {
		tests := []struct {
			name               string
			requestPath        string
			authStatusCode     int
			pathMappings       []internal.PathMappingConfig
			expectedStatusCode int
		}{
			{
				name:           "single path mapping matches",
				requestPath:    "/api/users",
				authStatusCode: http.StatusUnauthorized,
				pathMappings: []internal.PathMappingConfig{
					{
						Path: "/api",
						Mappings: map[int]int{
							http.StatusUnauthorized: http.StatusForbidden,
						},
					},
				},
				expectedStatusCode: http.StatusForbidden,
			},
			{
				name:           "path doesn't match - no mapping applied",
				requestPath:    "/web/dashboard",
				authStatusCode: http.StatusUnauthorized,
				pathMappings: []internal.PathMappingConfig{
					{
						Path: "/api",
						Mappings: map[int]int{
							http.StatusUnauthorized: http.StatusForbidden,
						},
					},
				},
				expectedStatusCode: http.StatusUnauthorized,
			},
			{
				name:           "multiple path mappings - longest match wins",
				requestPath:    "/api/v1/users",
				authStatusCode: http.StatusUnauthorized,
				pathMappings: []internal.PathMappingConfig{
					{
						Path: "/api",
						Mappings: map[int]int{
							http.StatusUnauthorized: http.StatusForbidden,
						},
					},
					{
						Path: "/api/v1",
						Mappings: map[int]int{
							http.StatusUnauthorized: http.StatusTeapot, // 418
						},
					},
				},
				expectedStatusCode: http.StatusTeapot,
			},
			{
				name:           "path matches but status code not in mapping",
				requestPath:    "/api/users",
				authStatusCode: http.StatusNotFound,
				pathMappings: []internal.PathMappingConfig{
					{
						Path: "/api",
						Mappings: map[int]int{
							http.StatusUnauthorized: http.StatusForbidden,
						},
					},
				},
				expectedStatusCode: http.StatusNotFound,
			},
			{
				name:           "exact path match takes precedence",
				requestPath:    "/api/v1/users/123",
				authStatusCode: http.StatusUnauthorized,
				pathMappings: []internal.PathMappingConfig{
					{
						Path: "/api",
						Mappings: map[int]int{
							http.StatusUnauthorized: http.StatusForbidden,
						},
					},
					{
						Path: "/api/v1/users",
						Mappings: map[int]int{
							http.StatusUnauthorized: http.StatusGone,
						},
					},
					{
						Path: "/api/v1",
						Mappings: map[int]int{
							http.StatusUnauthorized: http.StatusTeapot,
						},
					},
				},
				expectedStatusCode: http.StatusGone,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Create auth server that returns the specified status code
				authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.authStatusCode)
					_, _ = w.Write([]byte("Auth response"))
				}))
				defer authServer.Close()

				config := plugin.CreateConfig()
				config.Address = authServer.URL
				config.StatusCodePathMappings = tt.pathMappings

				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("next handler should not be called for non-2xx auth response")
				})

				handler, err := plugin.New(context.Background(), next, config, "test-plugin")
				test.RequireNoError(t, err)

				req := httptest.NewRequest(http.MethodGet, "http://example.com"+tt.requestPath, nil)
				recorder := httptest.NewRecorder()

				handler.ServeHTTP(recorder, req)

				test.AssertEqual(t, tt.expectedStatusCode, recorder.Code)
				test.AssertEqual(t, "Auth response", recorder.Body.String())
			})
		}
	})

	t.Run("path mapping takes precedence over global mapping", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Auth response"))
		}))
		defer authServer.Close()

		config := plugin.CreateConfig()
		config.Address = authServer.URL
		config.StatusCodeGlobalMappings = map[int]int{
			http.StatusUnauthorized: http.StatusForbidden,
		}
		config.StatusCodePathMappings = []internal.PathMappingConfig{
			{
				Path: "/api",
				Mappings: map[int]int{
					http.StatusUnauthorized: http.StatusTeapot,
				},
			},
		}

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called for non-2xx auth response")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		test.RequireNoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/users", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		// Path mapping should take precedence over global mapping
		test.AssertEqual(t, http.StatusTeapot, recorder.Code)
		test.AssertEqual(t, "Auth response", recorder.Body.String())
	})

	t.Run("no path match falls back to global mapping", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Auth response"))
		}))
		defer authServer.Close()

		config := plugin.CreateConfig()
		config.Address = authServer.URL
		config.StatusCodeGlobalMappings = map[int]int{
			http.StatusUnauthorized: http.StatusForbidden,
		}
		config.StatusCodePathMappings = []internal.PathMappingConfig{
			{
				Path: "/api",
				Mappings: map[int]int{
					http.StatusUnauthorized: http.StatusTeapot,
				},
			},
		}

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called for non-2xx auth response")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		test.RequireNoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/web/dashboard", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		// Should fall back to global mapping since /web doesn't match /api
		test.AssertEqual(t, http.StatusForbidden, recorder.Code)
		test.AssertEqual(t, "Auth response", recorder.Body.String())
	})

	t.Run("2xx status codes are not affected by mapping", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Auth-User", "john.doe")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		}))
		defer authServer.Close()

		config := plugin.CreateConfig()
		config.Address = authServer.URL
		config.StatusCodeGlobalMappings = map[int]int{
			http.StatusOK: http.StatusTeapot, // This should not be applied
		}
		config.AuthResponseHeaders = []string{"X-Auth-User"}

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			test.AssertEqual(t, "john.doe", r.Header.Get("X-Auth-User"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Success from next handler"))
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		test.RequireNoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		// 2xx status codes should not be mapped and should continue to next handler
		test.AssertEqual(t, http.StatusOK, recorder.Code)
		test.AssertEqual(t, "Success from next handler", recorder.Body.String())
	})

	t.Run("status code mapping preserves headers", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", "Bearer realm=\"API\"")
			w.Header().Set("X-Error-Code", "AUTH_FAILED")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
		}))
		defer authServer.Close()

		config := plugin.CreateConfig()
		config.Address = authServer.URL
		config.StatusCodeGlobalMappings = map[int]int{
			http.StatusUnauthorized: http.StatusForbidden,
		}

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called for non-2xx auth response")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		test.RequireNoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		test.AssertEqual(t, http.StatusForbidden, recorder.Code)
		test.AssertEqual(t, "Unauthorized", recorder.Body.String())
		// Check that headers are preserved - they should be copied from auth response
		wwwAuth := recorder.Header().Get("WWW-Authenticate")
		errorCode := recorder.Header().Get("X-Error-Code")
		test.AssertEqual(t, "Bearer realm=\"API\"", wwwAuth, "WWW-Authenticate header should be preserved")
		test.AssertEqual(t, "AUTH_FAILED", errorCode, "X-Error-Code header should be preserved")
	})
}
