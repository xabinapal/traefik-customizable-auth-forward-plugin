package traefik_customizable_auth_forward_plugin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	plugin "github.com/xabinapal/traefik-customizable-auth-forward-plugin"
)

func TestServeHTTP_Returns200(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request auth headers
		assert.Equal(t, "example.com", r.Header.Get("X-Original-Host"))
		assert.Equal(t, "http", r.Header.Get("X-Original-Proto"))
		assert.Equal(t, "GET", r.Header.Get("X-Original-Method"))
		assert.Equal(t, "/test", r.Header.Get("X-Original-Uri"))

		// Return auth headers
		w.Header().Set("X-Auth-User", "john.doe")
		w.Header().Set("X-Auth-Email", "john@example.com")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer authServer.Close()

	// Setup plugin
	ctx := context.Background()
	config := plugin.CreateConfig()

	// Setup plugin config
	config.Address = authServer.URL
	config.HeaderPrefix = "X-Original"
	config.AuthResponseHeaders = []string{"X-Auth-User", "X-Auth-Email"}

	// Create a request handler
	var capturedReq *http.Request
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		capturedReq = req
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("Success"))
	})

	// Create the plugin
	handler, err := plugin.New(ctx, next, config, "test-plugin")
	require.NoError(t, err)

	// Create test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	recorder := httptest.NewRecorder()

	// Execute
	handler.ServeHTTP(recorder, req)

	// Verify the response
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "Success", recorder.Body.String())

	// Verify the auth headers
	require.NotNil(t, capturedReq)
	assert.Equal(t, "john.doe", capturedReq.Header.Get("X-Auth-User"))
	assert.Equal(t, "john@example.com", capturedReq.Header.Get("X-Auth-Email"))
}
