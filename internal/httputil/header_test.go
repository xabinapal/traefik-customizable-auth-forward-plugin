package httputil_test

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/httputil"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/test"
)

func TestCopyHeaders(t *testing.T) {
	t.Run("copies specified headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token123")
		srcHeaders.Set("X-API-Key", "key456")
		srcHeaders.Set("Content-Type", "application/json")
		srcHeaders.Set("X-Custom", "custom-value")

		dstHeaders := http.Header{}

		filter := []string{"Authorization", "X-API-Key"}
		httputil.CopyHeaders(srcHeaders, dstHeaders, filter)

		test.AssertEqual(t, "Bearer token123", dstHeaders.Get("Authorization"))
		test.AssertEqual(t, "key456", dstHeaders.Get("X-API-Key"))
		test.AssertEqual(t, "", dstHeaders.Get("Content-Type"))
		test.AssertEqual(t, "", dstHeaders.Get("X-Custom"))
	})

	t.Run("copies multiple values for same header", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Add("X-Custom", "value1")
		srcHeaders.Add("X-Custom", "value2")
		srcHeaders.Add("X-Custom", "value3")

		dstHeaders := http.Header{}

		filter := []string{"X-Custom"}
		httputil.CopyHeaders(srcHeaders, dstHeaders, filter)

		values := dstHeaders.Values("X-Custom")
		test.AssertLen(t, values, 3)
		test.AssertContains(t, values, "value1")
		test.AssertContains(t, values, "value2")
		test.AssertContains(t, values, "value3")
	})

	t.Run("empty filter copies no headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token123")

		dstHeaders := http.Header{}

		httputil.CopyHeaders(srcHeaders, dstHeaders, []string{})

		test.AssertEmpty(t, dstHeaders)
	})

	t.Run("nil filter copies no headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token123")

		dstHeaders := http.Header{}

		httputil.CopyHeaders(srcHeaders, dstHeaders, nil)

		test.AssertEmpty(t, dstHeaders)
	})

	t.Run("filter with non-existent headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token123")

		dstHeaders := http.Header{}

		filter := []string{"NonExistent", "AlsoNonExistent"}
		httputil.CopyHeaders(srcHeaders, dstHeaders, filter)

		test.AssertEmpty(t, dstHeaders)
	})

	t.Run("case insensitive header matching", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("authorization", "Bearer token123")
		srcHeaders.Set("X-API-KEY", "key456")

		dstHeaders := http.Header{}

		// HTTP headers are case-insensitive, but Go canonicalizes them
		filter := []string{"Authorization", "x-api-key"}
		httputil.CopyHeaders(srcHeaders, dstHeaders, filter)

		// Go's http.Header canonicalizes header names
		test.AssertEqual(t, "Bearer token123", dstHeaders.Get("Authorization"))
		test.AssertEqual(t, "key456", dstHeaders.Get("X-Api-Key"))
	})

	t.Run("adds to existing headers in destination", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("X-Custom", "new-value")

		dstHeaders := http.Header{}
		dstHeaders.Set("X-Custom", "existing-value")
		dstHeaders.Set("Other-Header", "other")

		filter := []string{"X-Custom"}
		httputil.CopyHeaders(srcHeaders, dstHeaders, filter)

		// Should add to existing header, not replace
		values := dstHeaders.Values("X-Custom")
		test.AssertLen(t, values, 2)
		test.AssertContains(t, values, "existing-value")
		test.AssertContains(t, values, "new-value")

		// Other headers should remain unchanged
		test.AssertEqual(t, "other", dstHeaders.Get("Other-Header"))
	})
}

func TestCopyHeadersRegex(t *testing.T) {
	t.Run("copies headers matching regex", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("X-Auth-User", "john")
		srcHeaders.Set("X-Auth-Role", "admin")
		srcHeaders.Set("X-Other-Header", "other")
		srcHeaders.Set("Authorization", "Bearer token")

		dstHeaders := http.Header{}

		regex := regexp.MustCompile("(?i)^X-Auth-.*")
		httputil.CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		test.AssertEqual(t, "john", dstHeaders.Get("X-Auth-User"))
		test.AssertEqual(t, "admin", dstHeaders.Get("X-Auth-Role"))
		test.AssertEqual(t, "", dstHeaders.Get("X-Other-Header"))
		test.AssertEqual(t, "", dstHeaders.Get("Authorization"))
	})

	t.Run("case insensitive regex matching", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("authorization", "Bearer token1")
		srcHeaders.Set("AUTHORIZATION", "Bearer token2")
		srcHeaders.Set("Authorization", "Bearer token3")

		dstHeaders := http.Header{}

		regex := regexp.MustCompile("(?i)^authorization$")
		httputil.CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		// Go canonicalizes header names, so only the last set value is preserved
		// http.Header.Set() replaces previous values
		values := dstHeaders.Values("Authorization")
		test.AssertLen(t, values, 1)
		test.AssertContains(t, values, "Bearer token3")
	})

	t.Run("nil regex copies no headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("X-Auth-User", "john")

		dstHeaders := http.Header{}

		httputil.CopyHeadersRegex(srcHeaders, dstHeaders, nil)

		test.AssertEmpty(t, dstHeaders)
	})

	t.Run("regex with no matches copies no headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token")
		srcHeaders.Set("Content-Type", "application/json")

		dstHeaders := http.Header{}

		regex := regexp.MustCompile("(?i)^X-NonExistent-.*")
		httputil.CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		test.AssertEmpty(t, dstHeaders)
	})

	t.Run("complex regex patterns", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("X-Custom-Header", "value1")
		srcHeaders.Set("X-Custom-Other", "value2")
		srcHeaders.Set("Y-Custom-Header", "value3")
		srcHeaders.Set("X-Other-Header", "value4")

		dstHeaders := http.Header{}

		// Match headers starting with X-Custom-
		regex := regexp.MustCompile("(?i)^X-Custom-.*")
		httputil.CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		test.AssertEqual(t, "value1", dstHeaders.Get("X-Custom-Header"))
		test.AssertEqual(t, "value2", dstHeaders.Get("X-Custom-Other"))
		test.AssertEqual(t, "", dstHeaders.Get("Y-Custom-Header"))
		test.AssertEqual(t, "", dstHeaders.Get("X-Other-Header"))
	})

	t.Run("multiple values per header with regex", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Add("X-Auth-Token", "token1")
		srcHeaders.Add("X-Auth-Token", "token2")
		srcHeaders.Add("X-Other", "other")

		dstHeaders := http.Header{}

		regex := regexp.MustCompile("(?i)^X-Auth-.*")
		httputil.CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		values := dstHeaders.Values("X-Auth-Token")
		test.AssertLen(t, values, 2)
		test.AssertContains(t, values, "token1")
		test.AssertContains(t, values, "token2")
		test.AssertEqual(t, "", dstHeaders.Get("X-Other"))
	})

	t.Run("adds to existing headers in destination", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("X-Auth-User", "new-user")

		dstHeaders := http.Header{}
		dstHeaders.Set("X-Auth-User", "existing-user")
		dstHeaders.Set("Other-Header", "other")

		regex := regexp.MustCompile("(?i)^X-Auth-.*")
		httputil.CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		// Should add to existing header
		values := dstHeaders.Values("X-Auth-User")
		test.AssertLen(t, values, 2)
		test.AssertContains(t, values, "existing-user")
		test.AssertContains(t, values, "new-user")

		// Other headers should remain unchanged
		test.AssertEqual(t, "other", dstHeaders.Get("Other-Header"))
	})
}
