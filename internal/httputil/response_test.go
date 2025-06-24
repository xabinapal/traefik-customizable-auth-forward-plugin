package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/httputil"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal/test"
)

func TestNewResponseModifier(t *testing.T) {
	recorder := httptest.NewRecorder()
	rm := httputil.NewResponseModifier(recorder)

	test.AssertNotNil(t, rm)
	test.AssertEqual(t, recorder, rm.ResponseWriter)
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
		test.RequireLen(t, cookies, 1)
		test.AssertEqual(t, "session", cookies[0].Name)
		test.AssertEqual(t, "abc123", cookies[0].Value)
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
		test.RequireLen(t, cookies, 2)

		cookieMap := make(map[string]string)
		for _, c := range cookies {
			cookieMap[c.Name] = c.Value
		}

		test.AssertEqual(t, "abc123", cookieMap["session"])
		test.AssertEqual(t, "john", cookieMap["user"])
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
		test.RequireLen(t, cookies, 1)
		test.AssertEqual(t, "session", cookies[0].Name)
		test.AssertEqual(t, "new", cookies[0].Value)
	})
}

func TestResponseModifier_WriteHeader(t *testing.T) {
	t.Run("preserves existing headers", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		recorder.Header().Set("Content-Type", "application/json")
		recorder.Header().Set("X-Custom", "value")

		rm := httputil.NewResponseModifier(recorder)
		rm.WriteHeader(http.StatusCreated)

		test.AssertEqual(t, http.StatusCreated, recorder.Code)
		test.AssertEqual(t, "application/json", recorder.Header().Get("Content-Type"))
		test.AssertEqual(t, "value", recorder.Header().Get("X-Custom"))
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
		test.RequireLen(t, setCookieHeaders, 1)
		test.AssertContains(t, setCookieHeaders[0], "session=abc123")
		test.AssertContains(t, setCookieHeaders[0], "Path=/")
		test.AssertContains(t, setCookieHeaders[0], "HttpOnly")
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
		test.RequireLen(t, setCookieHeaders, 3)

		cookieStrings := strings.Join(setCookieHeaders, "; ")
		test.AssertContains(t, cookieStrings, "existing=cookie1")
		test.AssertContains(t, cookieStrings, "other=cookie2")
		test.AssertContains(t, cookieStrings, "new=cookie3")
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
		test.RequireLen(t, setCookieHeaders, 1)
		test.AssertContains(t, setCookieHeaders[0], "session=existing")
		test.AssertNotContains(t, setCookieHeaders[0], "session=new")
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
		test.RequireLen(t, setCookieHeaders, 2)

		cookieStrings := strings.Join(setCookieHeaders, "; ")
		test.AssertContains(t, cookieStrings, "valid=cookie")
		test.AssertContains(t, cookieStrings, "new=value")
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
		test.RequireLen(t, setCookieHeaders, 2)

		// The existing malformed cookie should be preserved as-is
		test.AssertContains(t, setCookieHeaders[0], "first=value1; second=value2")
		test.AssertContains(t, setCookieHeaders[1], "third=value3")
	})
}

func TestResponseModifier_Write(t *testing.T) {
	t.Run("forwards writes to underlying ResponseWriter", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rm := httputil.NewResponseModifier(recorder)

		data := []byte("test response data")
		n, err := rm.Write(data)

		test.RequireNoError(t, err)
		test.AssertEqual(t, len(data), n)
		test.AssertEqual(t, "test response data", recorder.Body.String())
	})
}

func TestResponseModifier_Header(t *testing.T) {
	t.Run("forwards Header calls to underlying ResponseWriter", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		rm := httputil.NewResponseModifier(recorder)

		rm.Header().Set("Content-Type", "application/json")
		rm.Header().Add("X-Custom", "value1")
		rm.Header().Add("X-Custom", "value2")

		test.AssertEqual(t, "application/json", recorder.Header().Get("Content-Type"))

		customValues := recorder.Header().Values("X-Custom")
		test.AssertLen(t, customValues, 2)
		test.AssertContains(t, customValues, "value1")
		test.AssertContains(t, customValues, "value2")
	})
}
