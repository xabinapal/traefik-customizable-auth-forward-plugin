package internal_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal"
)

func TestCreateAuthRequest(t *testing.T) {
	config := &internal.Config{
		Address: "http://localhost:8080",
	}

	client, err := internal.CreateClient(config)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	authReq, err := client.CreateAuthRequest(req)

	// Verify the request is created correctly
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", authReq.URL.String())
}

func TestCreateAuthRequest_PreserveMethod(t *testing.T) {
	config := &internal.Config{
		Address:               "http://localhost:8080",
		PreserveRequestMethod: true,
	}

	client, err := internal.CreateClient(config)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", nil)
	authReq, err := client.CreateAuthRequest(req)

	// Verify the request is created correctly
	require.NoError(t, err)
	assert.Equal(t, "POST", authReq.Method)
}

func TestDo_Returns200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return auth headers
		w.Header().Set("X-Auth-User", "john.doe")
		w.Header().Set("X-Auth-Email", "john@example.com")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &internal.Config{
		Address: server.URL,
	}

	client, err := internal.CreateClient(config)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	authReq, _ := client.CreateAuthRequest(req)
	authRes, err := client.Do(authReq)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, authRes.StatusCode)
	assert.Equal(t, "john.doe", authRes.Header.Get("X-Auth-User"))
	assert.Equal(t, "john@example.com", authRes.Header.Get("X-Auth-Email"))
}

func TestDo_Returns401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	config := &internal.Config{
		Address: server.URL,
	}

	client, err := internal.CreateClient(config)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	authReq, _ := client.CreateAuthRequest(req)
	authRes, err := client.Do(authReq)

	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, authRes.StatusCode)
}
