package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/httputil"
)

func TestNewResponseModifier(t *testing.T) {
	recorder := httptest.NewRecorder()
	rm := httputil.NewResponseModifier(recorder)

	assert.NotNil(t, rm)
	assert.Equal(t, recorder, rm.ResponseWriter)
}

func TestResponseModifier_AddCookie(t *testing.T) {
	t.Run("adds single cookie", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rm := httputil.NewResponseModifier(recorder)

		cookie := &http.Cookie{Name: "session", Value: "abc123"}
		rm.AddCookie(cookie)

		// WriteHeader should be called to set cookies
		rm.WriteHeader(http.StatusOK)

		response := recorder.Result()
		cookies := response.Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, "session", cookies[0].Name)
		assert.Equal(t, "abc123", cookies[0].Value)
	})

	t.Run("adds multiple cookies", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rm := httputil.NewResponseModifier(recorder)

		cookie1 := &http.Cookie{Name: "session", Value: "abc123"}
		cookie2 := &http.Cookie{Name: "user", Value: "john"}
		rm.AddCookie(cookie1)
		rm.AddCookie(cookie2)

		rm.WriteHeader(http.StatusOK)

		response := recorder.Result()
		cookies := response.Cookies()
		require.Len(t, cookies, 2)

		cookieMap := make(map[string]string)
		for _, c := range cookies {
			cookieMap[c.Name] = c.Value
		}

		assert.Equal(t, "abc123", cookieMap["session"])
		assert.Equal(t, "john", cookieMap["user"])
	})

	t.Run("overwrites cookie with same name", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rm := httputil.NewResponseModifier(recorder)

		cookie1 := &http.Cookie{Name: "session", Value: "old"}
		cookie2 := &http.Cookie{Name: "session", Value: "new"}
		rm.AddCookie(cookie1)
		rm.AddCookie(cookie2)

		rm.WriteHeader(http.StatusOK)

		response := recorder.Result()
		cookies := response.Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, "session", cookies[0].Name)
		assert.Equal(t, "new", cookies[0].Value)
	})
}

func TestResponseModifier_WriteHeader(t *testing.T) {
	t.Run("preserves existing headers", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Type", "application/json")
		recorder.Header().Set("X-Custom", "value")

		rm := httputil.NewResponseModifier(recorder)
		rm.WriteHeader(http.StatusCreated)

		assert.Equal(t, http.StatusCreated, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		assert.Equal(t, "value", recorder.Header().Get("X-Custom"))
	})

	t.Run("adds cookies to response", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rm := httputil.NewResponseModifier(recorder)

		cookie := &http.Cookie{
			Name:     "session",
			Value:    "abc123",
			Path:     "/",
			HttpOnly: true,
		}
		rm.AddCookie(cookie)

		rm.WriteHeader(http.StatusOK)

		setCookieHeaders := recorder.Header().Values("Set-Cookie")
		require.Len(t, setCookieHeaders, 1)
		assert.Contains(t, setCookieHeaders[0], "session=abc123")
		assert.Contains(t, setCookieHeaders[0], "Path=/")
		assert.Contains(t, setCookieHeaders[0], "HttpOnly")
	})

	t.Run("preserves existing Set-Cookie headers", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		recorder.Header().Add("Set-Cookie", "existing=cookie1; Path=/api")
		recorder.Header().Add("Set-Cookie", "other=cookie2; Secure")

		rm := httputil.NewResponseModifier(recorder)

		newCookie := &http.Cookie{Name: "new", Value: "cookie3"}
		rm.AddCookie(newCookie)

		rm.WriteHeader(http.StatusOK)

		setCookieHeaders := recorder.Header().Values("Set-Cookie")
		require.Len(t, setCookieHeaders, 3)

		cookieStrings := strings.Join(setCookieHeaders, "; ")
		assert.Contains(t, cookieStrings, "existing=cookie1")
		assert.Contains(t, cookieStrings, "other=cookie2")
		assert.Contains(t, cookieStrings, "new=cookie3")
	})

	t.Run("avoids duplicate cookies", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		recorder.Header().Add("Set-Cookie", "session=existing; Path=/")

		rm := httputil.NewResponseModifier(recorder)

		// Try to add cookie with same name
		duplicateCookie := &http.Cookie{Name: "session", Value: "new"}
		rm.AddCookie(duplicateCookie)

		rm.WriteHeader(http.StatusOK)

		setCookieHeaders := recorder.Header().Values("Set-Cookie")
		// Should only have the existing cookie, not the duplicate
		require.Len(t, setCookieHeaders, 1)
		assert.Contains(t, setCookieHeaders[0], "session=existing")
		assert.NotContains(t, setCookieHeaders[0], "session=new")
	})

	t.Run("handles malformed existing cookies gracefully", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		recorder.Header().Add("Set-Cookie", "") // Empty cookie
		recorder.Header().Add("Set-Cookie", "valid=cookie")

		rm := httputil.NewResponseModifier(recorder)

		newCookie := &http.Cookie{Name: "new", Value: "value"}
		rm.AddCookie(newCookie)

		rm.WriteHeader(http.StatusOK)

		setCookieHeaders := recorder.Header().Values("Set-Cookie")
		// Should have valid cookie + new cookie (empty cookie filtered out)
		require.Len(t, setCookieHeaders, 2)

		cookieStrings := strings.Join(setCookieHeaders, "; ")
		assert.Contains(t, cookieStrings, "valid=cookie")
		assert.Contains(t, cookieStrings, "new=value")
	})

	t.Run("handles multiple values in single cookie header", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		// This is technically invalid HTTP, but let's handle it gracefully
		recorder.Header().Add("Set-Cookie", "first=value1; second=value2")

		rm := httputil.NewResponseModifier(recorder)

		newCookie := &http.Cookie{Name: "third", Value: "value3"}
		rm.AddCookie(newCookie)

		rm.WriteHeader(http.StatusOK)

		setCookieHeaders := recorder.Header().Values("Set-Cookie")
		require.Len(t, setCookieHeaders, 2)

		// The existing malformed cookie should be preserved as-is
		assert.Contains(t, setCookieHeaders[0], "first=value1; second=value2")
		assert.Contains(t, setCookieHeaders[1], "third=value3")
	})
}

func TestResponseModifier_Write(t *testing.T) {
	t.Run("forwards writes to underlying ResponseWriter", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rm := httputil.NewResponseModifier(recorder)

		data := []byte("test response data")
		n, err := rm.Write(data)

		require.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, "test response data", recorder.Body.String())
	})
}

func TestResponseModifier_Header(t *testing.T) {
	t.Run("forwards Header calls to underlying ResponseWriter", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rm := httputil.NewResponseModifier(recorder)

		rm.Header().Set("Content-Type", "application/json")
		rm.Header().Add("X-Custom", "value1")
		rm.Header().Add("X-Custom", "value2")

		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

		customValues := recorder.Header().Values("X-Custom")
		assert.Len(t, customValues, 2)
		assert.Contains(t, customValues, "value1")
		assert.Contains(t, customValues, "value2")
	})
}
