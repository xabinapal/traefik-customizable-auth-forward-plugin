# Test Server

A simple HTTP server for testing the Traefik Customizable Forward Auth Plugin.

## Quick Start

### Local

```bash
# install dependencies
npm install

# start server
npm start

# or with auto-reload
npm run dev
```

### Docker

```bash
# build container image
docker build -t traefik-customizable-auth-forward-test-server .

# run container
docker run --rm -p 3000:3000 traefik-customizable-auth-forward-test-server
```

## Usage

### Debug Information
```bash
curl -H "X-Original-Host: app.example.com" \
     -H "X-Original-Proto: https" \
     http://localhost:3000/debug
```

### Basic Authentication

```bash
# returns 200 with auth headers
curl -v http://localhost:3000/auth

# returns 401 unauthorized
curl -v http://localhost:3000/auth/deny

# returns 302 redirect
curl -v http://localhost:3000/auth/redirect
```


## Traefik Configuration

```yaml
# success
- traefik.http.routers.whoami.middlewares=auth
- traefik.http.middlewares.auth.plugin.customizable-forward-auth.address=http://test-server:3000/auth

# deny
- traefik.http.routers.whoami.middlewares=auth-deny
- traefik.http.middlewares.auth-deny.plugin.customizable-forward-auth.address=http://test-server:3000/auth/deny
```