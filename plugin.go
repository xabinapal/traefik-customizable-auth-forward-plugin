package traefik_customizable_auth_forward_plugin

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
		HeaderPrefix:             defaultHeaderPrefix,
		TrustForwardHeader:       false,
		AuthRequestHeaders:       []string{},
		AddAuthCookiesToResponse: []string{},
		AuthResponseHeaders:      []string{},
		AuthResponseHeadersRegex: "",
		ForwardBody:              false,
		MaxBodySize:              -1,
		HeaderField:              "",
		PreserveRequestMethod:    false,
		PreserveLocationHeader:   false,
	}
}

func New(ctx context.Context, next http.Handler, config *internal.Config, name string) (http.Handler, error) {
	// Validate config
	if config.Address == "" {
		return nil, fmt.Errorf("address cannot be empty")
	}

	// Create HTTP client with custom configuration
	client := internal.CreateClient(config)

	plugin := &Plugin{
		next:   next,
		name:   name,
		config: config,
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
	defer authRes.Body.Close()

	fmt.Printf("auth request returned status code %v\n", authRes.StatusCode)

	// If auth service returns non-2xx status, forward its response
	if authRes.StatusCode < http.StatusOK || authRes.StatusCode >= http.StatusMultipleChoices {

		rw.WriteHeader(authRes.StatusCode)
		if _, err := io.Copy(rw, authRes.Body); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}

	cfa.next.ServeHTTP(rw, authReq)
}
