package httputil_test

import (
	"net/http"
	"testing"

	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/httputil"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/test"
)

func TestCopyCookies(t *testing.T) {
	t.Run("copies specified cookies", func(t *testing.T) {
		// Create source request with cookies
		srcReq, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
		srcReq.AddCookie(&http.Cookie{Name: "user", Value: "john"})
		srcReq.AddCookie(&http.Cookie{Name: "csrf", Value: "token456"})
		srcReq.AddCookie(&http.Cookie{Name: "other", Value: "skip"})

		// Create destination request
		dstReq, _ := http.NewRequest(http.MethodGet, "http://auth.example.com", nil)

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

		test.AssertLen(t, cookies, 2)
		test.AssertContains(t, cookieNames, "session")
		test.AssertContains(t, cookieNames, "user")
		test.AssertNotContains(t, cookieNames, "csrf")
		test.AssertNotContains(t, cookieNames, "other")
		test.AssertEqual(t, "abc123", cookieValues["session"])
		test.AssertEqual(t, "john", cookieValues["user"])
	})

	t.Run("empty filter copies no cookies", func(t *testing.T) {
		srcReq, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest(http.MethodGet, "http://auth.example.com", nil)

		httputil.CopyCookies(srcReq, dstReq, []string{})

		test.AssertEmpty(t, dstReq.Cookies())
	})

	t.Run("nil filter copies no cookies", func(t *testing.T) {
		srcReq, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest(http.MethodGet, "http://auth.example.com", nil)

		httputil.CopyCookies(srcReq, dstReq, nil)

		test.AssertEmpty(t, dstReq.Cookies())
	})

	t.Run("filter with non-existent cookie names", func(t *testing.T) {
		srcReq, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest(http.MethodGet, "http://auth.example.com", nil)

		filter := []string{"nonexistent", "alsononexistent"}
		httputil.CopyCookies(srcReq, dstReq, filter)

		test.AssertEmpty(t, dstReq.Cookies())
	})

	t.Run("duplicate cookie names in filter", func(t *testing.T) {
		srcReq, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		srcReq.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

		dstReq, _ := http.NewRequest(http.MethodGet, "http://auth.example.com", nil)

		filter := []string{"session", "session", "session"}
		httputil.CopyCookies(srcReq, dstReq, filter)

		// Should only copy once despite multiple entries in filter
		cookies := dstReq.Cookies()
		test.AssertLen(t, cookies, 1)
		test.AssertEqual(t, "session", cookies[0].Name)
		test.AssertEqual(t, "abc123", cookies[0].Value)
	})

	t.Run("cookies with same name but different attributes", func(t *testing.T) {
		srcReq, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		cookie := &http.Cookie{
			Name:     "session",
			Value:    "abc123",
			Path:     "/api",
			Domain:   "example.com",
			HttpOnly: true,
			Secure:   true,
		}
		srcReq.AddCookie(cookie)

		dstReq, _ := http.NewRequest(http.MethodGet, "http://auth.example.com", nil)

		filter := []string{"session"}
		httputil.CopyCookies(srcReq, dstReq, filter)

		cookies := dstReq.Cookies()
		test.AssertLen(t, cookies, 1)
		copiedCookie := cookies[0]
		test.AssertEqual(t, "session", copiedCookie.Name)
		test.AssertEqual(t, "abc123", copiedCookie.Value)
		// Note: Go's AddCookie method only preserves Name and Value
		// Other attributes are not copied by the CopyCookies function
		test.AssertEqual(t, "", copiedCookie.Path)
		test.AssertEqual(t, "", copiedCookie.Domain)
		test.AssertFalse(t, copiedCookie.HttpOnly)
		test.AssertFalse(t, copiedCookie.Secure)
	})
}
