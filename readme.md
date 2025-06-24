# Traefik Customizable Auth Forward Plugin

<div align="center">
  
  <img src="./.assets/icon.svg" width="128" alt="Traefik Customizable Forward Auth Plugin">

</div>

<div align="center">

  **Made with ❤️ for the Traefik community** \
  ⭐ [Star repo](https://github.com/xabinapal/traefik-customizable-auth-forward-plugin/stargazers)
  🐛 [Report bug](https://github.com/xabinapal/traefik-customizable-auth-forward-plugin/issues)
  💡 [Request feature](https://github.com/xabinapal/traefik-customizable-auth-forward-plugin/issues)

</div>

<div align="center">

  **If this plugin helps you, consider supporting me** \
  [![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/xabinapal)

</div>

## Overview

This plugin extends Traefik's built-in `forwardAuth` middleware with additional customization capabilities while maintaining full backward compatibility. You can replace any existing `forwardAuth` middleware configuration with this plugin without any changes, and then optionally enhance it with the new features.

**Key enhancements over native middleware:**

- **Customizable headers**: Rename standard `X-Forwarded-*` headers sent to authentication servers to prevent conflicts with proxies or balancers.
- **Absolute URL header**: Send the complete original request URL in a single header for authentication servers that require it.
- **Request customization**: Fine-tune communication with your authentication server through configurable timeouts and TLS settings.
- **Enhanced header/cookie management**: More granular control over which headers and cookies are copied to/from the authentication server.
- **Status code mappings**: Customize HTTP status codes returned by the authentication server with global and path-based mappings.

## Installation

> **Note**: This plugin is only supported in Traefik `v2.11.1` or later, as it's the first version that bundles Yaegi `v0.16.1`, required to run Go 1.22 code.

Add the plugin to your Traefik configuration using the experimental plugins feature:

**File**

```yaml
experimental:
  plugins:
    customizable-auth-forward:
      moduleName: "github.com/xabinapal/traefik-customizable-auth-forward-plugin"
      version: "v1.0.0"
```

**CLI**

```sh
--experimental.plugins.customizable-auth-forward.modulename=github.com/xabinapal/traefik-customizable-auth-forward-plugin
--experimental.plugins.customizable-auth-forward.version=v1.0.0
```

## Compatibility

This plugin is a **100% drop-in replacement** for Traefik's native `forwardAuth` middleware. If you are not using the extended capabilities of this middleware, your existing configurations will work without modification.

```yaml
# From this:
middlewares:
  my-auth:
    forwardAuth:
      address: "https://my-auth-server.example.com/auth"

# To this:
middlewares:
  my-auth:
    plugin:
      customizable-auth-forward:
        address: "https://my-auth-server.example.com/auth"
```

## Configuration

- `address`: `string`, **required**
    - Absolute URL of the authentication service.

- `timeout`: `duration`, optional, default `30s`
    - Timeout for requests to the authentication service.

- `tls.ca`: `string`, optional
    - Path to the CA certificate file to check when connecting to the authentication service.

- `tls.cert`: `string`, optional
    - Path to the client certificate file to use when connecting to the authentication service.

- `tls.key`: `string`, optional
    - Path to the client private key file to use when connecting to the authentication service.

- `tls.minVersion`: `uint16`, optional, default `12`
    - Minimum TLS version required in secure communication to the authentication service.
    - Allowed values are `10` (`TLS1.0`), `11` (`TLS1.1`), `12` (`TLS1.2`) and `13` (`TLS1.3`).

- `tls.maxVersion`: `uint16`, optional, default `13`
    - Maximum TLS version required in secure communication to the authentication service.
    - Allowed values are `10` (`TLS1.0`), `11` (`TLS1.1`), `12` (`TLS1.2`) and `13` (`TLS1.3`).

- `tls.insecureSkipVerify`: `bool`, optional, default `false`
    - Skip TLS certificate verification when connecting to the authentication service.

- `headerPrefix`: `string`, optional, default `X-Forwarded`
    - Prefix for original request headers sent to the authentication service.
    - E.g., `X-Original` will send headers like `X-Forwarded-Host` and `X-Original-Host`.

- `absoluteUrlHeader`: `string`, optional
    - Extra header name to send the complete original URL, will be prefixed with `headerPrefix`.
    - E.g., `Absolute-Url` will send a header `X-Forwarded-Absolute-Url`.

- `trustForwardHeader`: `bool`, optional, default `false`
    - Get `X-Forwarded` header values from the original request when sending original request info to the authentication service.

- `preserveRequestMethod`: `bool`, optional, default `false`
    - Preserve the original HTTP method received when forwarding to the authentication service.
    - If not set, it will always send `GET` requests.

- `authRequestHeaders`: `[]string`, optional
    - List of headers to forward from the original request to the authentication service request.
    - Both this and `authRequestHeadersRegex` can be set at the same time.

- `authRequestHeadersRegex`: `string`, optional
    - Regex pattern to match headers to forward from the original request to authentication service request.
    - Both this and `authRequestHeaders` can be set at the same time.

- `authRequestCookies`: `[]string`, optional
    - List of cookie names to forward from the original request to the authentication service request.

- `authResponseHeaders`: `[]string`, optional
    - List of headers to copy from the authentication service response to the upstream request.
    - Both this and `authResponseHeadersRegex` can be set at the same time.

- `authResponseHeadersRegex`: `string`, optional
    - Regex pattern to match headers to copy from the authentication service response to the upstream request.
    - Both this and `authResponseHeaders` can be set at the same time.

- `addAuthCookiesToResponse`: `[]string`, optional
    - List of cookie names to copy from the authentication response to the upstream request.

- `preserveLocationHeader`: `bool`, optional, default `false`
    - Whether to convert the `Location` header of the autentication server to an absolute URL with its domain.
    - It only takes effect when authentication responses are not `2xx` and contain a `Location` header with a relative URL.

- `forwardBody`: `bool`, optional, default `false`
    - Forward original upstream body to the authentication service.

- `maxBodySize`: `int64`, optional, default `-1`
    - Maximum size of body to forward to the authentication service.
    - `-1` will send the entire body. Every other value will truncate the body if it is larger.

- `statusCodeGlobalMappings`: `map[int]int`, optional
    - Global mapping of authentication service status codes to different status codes.
    - Applied to all non-2xx requests unless overridden by path-specific mappings.
    - E.g., `{401: 403}` will return `403 Forbidden` instead of `401 Unauthorized`.

- `statusCodePathMappings`: `[]PathMappingConfig`, optional
    - Path-based mapping of authentication service status codes to different status codes.
    - Takes precedence over global mappings when the request path matches.
    - Each mapping has a `path` string and a `mappings` map of status codes.
    - Longest matching path takes precedence when multiple paths match.

## Examples

### File YAML Provider

```yaml
http:
  middlewares:
    my-auth:
      plugin:
        customizable-auth-forward:
          address: https://my-auth-server.example.com/auth
          timeout: 10s
          tls:
            minVersion: 13
            insecureSkipVerify: false
          headerPrefix: X-Original
          absoluteUrlHeader: Absolute-Url
          authRequestCookies:
            - __auth_session
          authResponseHeadersRegex: ^X-Auth-.*
          addAuthCookiesToResponse:
            - __auth_identity
            - __auth_csrf
          statusCodeGlobalMappings:
            401: 403
            404: 410
          statusCodePathMappings:
            - path: /api/v1
              mappings:
                401: 418
                403: 451
            - path: /admin
              mappings:
                401: 404
                403: 404

  routers:
    api:
      rule: Host(`api.example.com`)
      middlewares:
        - my-auth
      service: api-service
```

### Kubernetes CRD Provider

**Middleware**

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: auth-middleware
spec:
  plugin:
    customizable-auth-forward:
      address: https://my-auth-server.example.com/auth
      timeout: 30s
      tls:
        minVersion: 13
        insecureSkipVerify: false
      headerPrefix: X-Original
      absoluteUrlHeader: Absolute-Url
      authRequestCookies:
        - __auth_session
      authResponseHeadersRegex: ^X-Auth-.*
      addAuthCookiesToResponse:
        - __auth_identity
        - __auth_csrf
      statusCodeGlobalMappings:
        401: 403
        404: 410
      statusCodePathMappings:
        - path: /api/v1
          mappings:
            401: 418
            403: 451
        - path: /admin
          mappings:
            401: 404
            403: 404
```

**IngressRoute**

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: api-route
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`api.example.com`)
      kind: Rule
      middlewares:
        - name: auth-middleware
      services:
        - name: api-service
          port: 80
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
