package traefik_customizable_auth_forward_plugin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	plugin "github.com/xabinapal/traefik-customizable-auth-forward-plugin"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal"
)

func TestCreateConfig(t *testing.T) {
	config := plugin.CreateConfig()

	// Verify all default values are set correctly
	assert.Equal(t, "", config.Address)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, "X-Forwarded", config.HeaderPrefix)
	assert.False(t, config.PreserveRequestMethod)
	assert.False(t, config.TrustForwardHeader)
	assert.False(t, config.PreserveLocationHeader)
	assert.False(t, config.ForwardBody)
	assert.Equal(t, int64(-1), config.MaxBodySize)

	// Verify TLS defaults
	require.NotNil(t, config.TLS)
	assert.Equal(t, "", config.TLS.CA)
	assert.Equal(t, "", config.TLS.Cert)
	assert.Equal(t, "", config.TLS.Key)
	assert.False(t, config.TLS.InsecureSkipVerify)

	// Verify slice fields are initialized
	assert.NotNil(t, config.AuthRequestHeaders)
	assert.NotNil(t, config.AuthRequestCookies)
	assert.NotNil(t, config.AuthResponseHeaders)
	assert.NotNil(t, config.AddAuthCookiesToResponse)
	assert.Len(t, config.AuthRequestHeaders, 0)
	assert.Len(t, config.AuthRequestCookies, 0)
	assert.Len(t, config.AuthResponseHeaders, 0)
	assert.Len(t, config.AddAuthCookiesToResponse, 0)
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("successful creation", func(t *testing.T) {
		config := &internal.Config{
			Address: "http://auth.example.com",
			Timeout: 10 * time.Second,
		}

		handler, err := plugin.New(ctx, next, config, "test-plugin")
		require.NoError(t, err)
		assert.NotNil(t, handler)
	})

	t.Run("empty address returns error", func(t *testing.T) {
		config := &internal.Config{
			Address: "",
			Timeout: 10 * time.Second,
		}

		handler, err := plugin.New(ctx, next, config, "test-plugin")
		assert.Error(t, err)
		assert.Nil(t, handler)
		assert.Contains(t, err.Error(), "address cannot be empty")
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		config := &internal.Config{
			Address:                 "http://auth.example.com",
			AuthRequestHeadersRegex: "[invalid-regex",
		}

		handler, err := plugin.New(ctx, next, config, "test-plugin")
		assert.Error(t, err)
		assert.Nil(t, handler)
		assert.Contains(t, err.Error(), "error parsing config")
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
				assert.Equal(t, "john.doe", req.Header.Get("X-Auth-User"))
				assert.Equal(t, "john@example.com", req.Header.Get("X-Auth-Email"))
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
				assert.Equal(t, "custom-value", req.Header.Get("X-Custom-Header"))
				assert.Equal(t, "other-value", req.Header.Get("X-Other-Header"))
				assert.Equal(t, "", req.Header.Get("Y-Skip-Header"))
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
				assert.True(t, sessionFound, "session cookie should be forwarded")
				assert.True(t, userFound, "user cookie should be forwarded")
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
				w.Write([]byte(tt.authBody))
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
				w.Write([]byte("Success from next handler"))
			})

			// Create plugin
			handler, err := plugin.New(context.Background(), next, config, "test-plugin")
			require.NoError(t, err)

			// Create test request
			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			if tt.setupRequest != nil {
				tt.setupRequest(req)
			}
			recorder := httptest.NewRecorder()

			// Execute
			handler.ServeHTTP(recorder, req)

			// Verify response
			assert.Equal(t, tt.expectedStatus, recorder.Code)
			assert.Equal(t, tt.expectedBody, recorder.Body.String())

			// Verify headers
			for key, value := range tt.expectedHeaders {
				if value == "DYNAMIC" && key == "Location" {
					// For dynamic location header, just check it contains /login
					location := recorder.Header().Get("Location")
					assert.Contains(t, location, "/login", "Location header should contain /login")
				} else {
					assert.Equal(t, value, recorder.Header().Get(key))
				}
			}

			// Verify next handler was called appropriately
			if tt.expectedStatus >= http.StatusOK && tt.expectedStatus < http.StatusMultipleChoices {
				assert.True(t, nextCalled, "next handler should be called for 2xx auth response")
			} else {
				assert.False(t, nextCalled, "next handler should not be called for non-2xx auth response")
			}
		})
	}
}

func TestServeHTTP_ErrorScenarios(t *testing.T) {
	t.Run("auth service unreachable", func(t *testing.T) {
		config := plugin.CreateConfig()
		config.Address = "http://nonexistent.example.com:99999"

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called when auth service is unreachable")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "dial tcp")
	})

	t.Run("malformed auth service URL", func(t *testing.T) {
		config := plugin.CreateConfig()
		config.Address = "://invalid-url"

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called with invalid auth URL")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "error creating auth request")
	})

	t.Run("auth service returns invalid location header", func(t *testing.T) {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "://invalid-location")
			w.WriteHeader(http.StatusFound)
			w.Write([]byte("Found"))
		}))
		defer authServer.Close()

		config := plugin.CreateConfig()
		config.Address = authServer.URL
		config.PreserveLocationHeader = true

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called for redirect response")
		})

		handler, err := plugin.New(context.Background(), next, config, "test-plugin")
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "http://example.com/test", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		// Should return 500 error when location parsing fails
		assert.Equal(t, http.StatusInternalServerError, recorder.Code)
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
				"X-Forwarded-Method": "GET",
				"X-Forwarded-Uri":    "http://example.com/test", // Request.RequestURI is full URL
			},
		},
		{
			name:         "custom header prefix",
			headerPrefix: "X-Original",
			expectedHeaders: map[string]string{
				"X-Original-Host":   "example.com",
				"X-Original-Proto":  "http",
				"X-Original-Method": "GET",
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
				w.Write([]byte("OK"))
			}))
			defer authServer.Close()

			config := plugin.CreateConfig()
			config.Address = authServer.URL
			config.HeaderPrefix = tt.headerPrefix

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler, err := plugin.New(context.Background(), next, config, "test-plugin")
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "http://example.com/test", nil)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)

			// Verify auth request headers
			for key, value := range tt.expectedHeaders {
				assert.Equal(t, value, capturedHeaders.Get(key), "header %s should be set correctly", key)
			}
		})
	}
}
