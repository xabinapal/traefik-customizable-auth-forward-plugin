package internal

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCopyCookies(t *testing.T) {
	t.Run("copies specified cookies", func(t *testing.T) {
		// Create source request with cookies
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
		srcReq.AddCookie(&http.Cookie{Name: "user", Value: "john"})
		srcReq.AddCookie(&http.Cookie{Name: "csrf", Value: "token456"})
		srcReq.AddCookie(&http.Cookie{Name: "other", Value: "skip"})

		// Create destination request
		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		// Copy specific cookies
		filter := []string{"session", "user"}
		CopyCookies(srcReq, dstReq, filter)

		// Verify cookies were copied
		cookies := dstReq.Cookies()
		cookieNames := make([]string, len(cookies))
		cookieValues := make(map[string]string)
		for i, cookie := range cookies {
			cookieNames[i] = cookie.Name
			cookieValues[cookie.Name] = cookie.Value
		}

		assert.Len(t, cookies, 2)
		assert.Contains(t, cookieNames, "session")
		assert.Contains(t, cookieNames, "user")
		assert.NotContains(t, cookieNames, "csrf")
		assert.NotContains(t, cookieNames, "other")
		assert.Equal(t, "abc123", cookieValues["session"])
		assert.Equal(t, "john", cookieValues["user"])
	})

	t.Run("empty filter copies no cookies", func(t *testing.T) {
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		CopyCookies(srcReq, dstReq, []string{})

		assert.Len(t, dstReq.Cookies(), 0)
	})

	t.Run("nil filter copies no cookies", func(t *testing.T) {
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		CopyCookies(srcReq, dstReq, nil)

		assert.Len(t, dstReq.Cookies(), 0)
	})

	t.Run("filter with non-existent cookie names", func(t *testing.T) {
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		filter := []string{"nonexistent", "alsononexistent"}
		CopyCookies(srcReq, dstReq, filter)

		assert.Len(t, dstReq.Cookies(), 0)
	})

	t.Run("duplicate cookie names in filter", func(t *testing.T) {
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		filter := []string{"session", "session", "session"}
		CopyCookies(srcReq, dstReq, filter)

		// Should only copy once despite multiple entries in filter
		cookies := dstReq.Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, "session", cookies[0].Name)
		assert.Equal(t, "abc123", cookies[0].Value)
	})

	t.Run("cookies with same name but different attributes", func(t *testing.T) {
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		cookie := &http.Cookie{
			Name:     "session",
			Value:    "abc123",
			Path:     "/api",
			Domain:   "example.com",
			HttpOnly: true,
			Secure:   true,
		}
		srcReq.AddCookie(cookie)

		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		filter := []string{"session"}
		CopyCookies(srcReq, dstReq, filter)

		cookies := dstReq.Cookies()
		assert.Len(t, cookies, 1)
		copiedCookie := cookies[0]
		assert.Equal(t, "session", copiedCookie.Name)
		assert.Equal(t, "abc123", copiedCookie.Value)
		// Note: Go's AddCookie method only preserves Name and Value
		// Other attributes are not copied by the CopyCookies function
		assert.Equal(t, "", copiedCookie.Path)
		assert.Equal(t, "", copiedCookie.Domain)
		assert.False(t, copiedCookie.HttpOnly)
		assert.False(t, copiedCookie.Secure)
	})
}

func TestCopyHeaders(t *testing.T) {
	t.Run("copies specified headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token123")
		srcHeaders.Set("X-API-Key", "key456")
		srcHeaders.Set("Content-Type", "application/json")
		srcHeaders.Set("X-Custom", "custom-value")

		dstHeaders := http.Header{}

		filter := []string{"Authorization", "X-API-Key"}
		CopyHeaders(srcHeaders, dstHeaders, filter)

		assert.Equal(t, "Bearer token123", dstHeaders.Get("Authorization"))
		assert.Equal(t, "key456", dstHeaders.Get("X-API-Key"))
		assert.Equal(t, "", dstHeaders.Get("Content-Type"))
		assert.Equal(t, "", dstHeaders.Get("X-Custom"))
	})

	t.Run("copies multiple values for same header", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Add("X-Custom", "value1")
		srcHeaders.Add("X-Custom", "value2")
		srcHeaders.Add("X-Custom", "value3")

		dstHeaders := http.Header{}

		filter := []string{"X-Custom"}
		CopyHeaders(srcHeaders, dstHeaders, filter)

		values := dstHeaders.Values("X-Custom")
		assert.Len(t, values, 3)
		assert.Contains(t, values, "value1")
		assert.Contains(t, values, "value2")
		assert.Contains(t, values, "value3")
	})

	t.Run("empty filter copies no headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token123")

		dstHeaders := http.Header{}

		CopyHeaders(srcHeaders, dstHeaders, []string{})

		assert.Len(t, dstHeaders, 0)
	})

	t.Run("nil filter copies no headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token123")

		dstHeaders := http.Header{}

		CopyHeaders(srcHeaders, dstHeaders, nil)

		assert.Len(t, dstHeaders, 0)
	})

	t.Run("filter with non-existent headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token123")

		dstHeaders := http.Header{}

		filter := []string{"NonExistent", "AlsoNonExistent"}
		CopyHeaders(srcHeaders, dstHeaders, filter)

		assert.Len(t, dstHeaders, 0)
	})

	t.Run("case insensitive header matching", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("authorization", "Bearer token123")
		srcHeaders.Set("X-API-KEY", "key456")

		dstHeaders := http.Header{}

		// HTTP headers are case-insensitive, but Go canonicalizes them
		filter := []string{"Authorization", "x-api-key"}
		CopyHeaders(srcHeaders, dstHeaders, filter)

		// Go's http.Header canonicalizes header names
		assert.Equal(t, "Bearer token123", dstHeaders.Get("Authorization"))
		assert.Equal(t, "key456", dstHeaders.Get("X-Api-Key"))
	})

	t.Run("adds to existing headers in destination", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("X-Custom", "new-value")

		dstHeaders := http.Header{}
		dstHeaders.Set("X-Custom", "existing-value")
		dstHeaders.Set("Other-Header", "other")

		filter := []string{"X-Custom"}
		CopyHeaders(srcHeaders, dstHeaders, filter)

		// Should add to existing header, not replace
		values := dstHeaders.Values("X-Custom")
		assert.Len(t, values, 2)
		assert.Contains(t, values, "existing-value")
		assert.Contains(t, values, "new-value")

		// Other headers should remain unchanged
		assert.Equal(t, "other", dstHeaders.Get("Other-Header"))
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
		CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		assert.Equal(t, "john", dstHeaders.Get("X-Auth-User"))
		assert.Equal(t, "admin", dstHeaders.Get("X-Auth-Role"))
		assert.Equal(t, "", dstHeaders.Get("X-Other-Header"))
		assert.Equal(t, "", dstHeaders.Get("Authorization"))
	})

	t.Run("case insensitive regex matching", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("authorization", "Bearer token1")
		srcHeaders.Set("AUTHORIZATION", "Bearer token2")
		srcHeaders.Set("Authorization", "Bearer token3")

		dstHeaders := http.Header{}

		regex := regexp.MustCompile("(?i)^authorization$")
		CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		// Go canonicalizes header names, so only the last set value is preserved
		// http.Header.Set() replaces previous values
		values := dstHeaders.Values("Authorization")
		assert.Len(t, values, 1)
		assert.Contains(t, values, "Bearer token3")
	})

	t.Run("nil regex copies no headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("X-Auth-User", "john")

		dstHeaders := http.Header{}

		CopyHeadersRegex(srcHeaders, dstHeaders, nil)

		assert.Len(t, dstHeaders, 0)
	})

	t.Run("regex with no matches copies no headers", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("Authorization", "Bearer token")
		srcHeaders.Set("Content-Type", "application/json")

		dstHeaders := http.Header{}

		regex := regexp.MustCompile("(?i)^X-NonExistent-.*")
		CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		assert.Len(t, dstHeaders, 0)
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
		CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		assert.Equal(t, "value1", dstHeaders.Get("X-Custom-Header"))
		assert.Equal(t, "value2", dstHeaders.Get("X-Custom-Other"))
		assert.Equal(t, "", dstHeaders.Get("Y-Custom-Header"))
		assert.Equal(t, "", dstHeaders.Get("X-Other-Header"))
	})

	t.Run("multiple values per header with regex", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Add("X-Auth-Token", "token1")
		srcHeaders.Add("X-Auth-Token", "token2")
		srcHeaders.Add("X-Other", "other")

		dstHeaders := http.Header{}

		regex := regexp.MustCompile("(?i)^X-Auth-.*")
		CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		values := dstHeaders.Values("X-Auth-Token")
		assert.Len(t, values, 2)
		assert.Contains(t, values, "token1")
		assert.Contains(t, values, "token2")
		assert.Equal(t, "", dstHeaders.Get("X-Other"))
	})

	t.Run("adds to existing headers in destination", func(t *testing.T) {
		srcHeaders := http.Header{}
		srcHeaders.Set("X-Auth-User", "new-user")

		dstHeaders := http.Header{}
		dstHeaders.Set("X-Auth-User", "existing-user")
		dstHeaders.Set("Other-Header", "other")

		regex := regexp.MustCompile("(?i)^X-Auth-.*")
		CopyHeadersRegex(srcHeaders, dstHeaders, regex)

		// Should add to existing header
		values := dstHeaders.Values("X-Auth-User")
		assert.Len(t, values, 2)
		assert.Contains(t, values, "existing-user")
		assert.Contains(t, values, "new-user")

		// Other headers should remain unchanged
		assert.Equal(t, "other", dstHeaders.Get("Other-Header"))
	})
}
