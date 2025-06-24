package httputil_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/httputil"
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
		httputil.CopyCookies(srcReq, dstReq, filter)

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

		httputil.CopyCookies(srcReq, dstReq, []string{})

		assert.Len(t, dstReq.Cookies(), 0)
	})

	t.Run("nil filter copies no cookies", func(t *testing.T) {
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		httputil.CopyCookies(srcReq, dstReq, nil)

		assert.Len(t, dstReq.Cookies(), 0)
	})

	t.Run("filter with non-existent cookie names", func(t *testing.T) {
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		filter := []string{"nonexistent", "alsononexistent"}
		httputil.CopyCookies(srcReq, dstReq, filter)

		assert.Len(t, dstReq.Cookies(), 0)
	})

	t.Run("duplicate cookie names in filter", func(t *testing.T) {
		srcReq, _ := http.NewRequest("GET", "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest("GET", "http://auth.example.com", nil)

		filter := []string{"session", "session", "session"}
		httputil.CopyCookies(srcReq, dstReq, filter)

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
		httputil.CopyCookies(srcReq, dstReq, filter)

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
