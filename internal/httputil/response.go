package httputil

import (
	"fmt"
	"net/http"
	"net/textproto"
	"slices"
	"strings"
)

type ResponseModifier struct {
	http.ResponseWriter

	cookies map[string]*http.Cookie
}

func NewResponseModifier(rw http.ResponseWriter) *ResponseModifier {
	return &ResponseModifier{
		ResponseWriter: rw,

		cookies: make(map[string]*http.Cookie),
	}
}

func (rm *ResponseModifier) AddCookie(cookie *http.Cookie) {
	rm.cookies[cookie.Name] = cookie
}

func (rm *ResponseModifier) WriteHeader(statusCode int) {
	existingCookies := rm.Header().Values("Set-Cookie")
	existingCookieNames := make([]string, len(existingCookies))

	rm.Header().Del("Set-Cookie")

	for _, cookieStr := range existingCookies {
		if cookieNames, err := parseCookieNames(cookieStr); err == nil {
			rm.Header().Add("Set-Cookie", cookieStr)
			existingCookieNames = append(existingCookieNames, cookieNames...)
		}
	}

	for _, cookie := range rm.cookies {
		if !slices.Contains(existingCookieNames, cookie.Name) {
			rm.Header().Add("Set-Cookie", cookie.String())
		}
	}

	rm.ResponseWriter.WriteHeader(statusCode)
}

func parseCookieNames(cookie string) ([]string, error) {
	parts := strings.Split(textproto.TrimString(cookie), ";")
	if len(parts) == 1 && parts[0] == "" {
		return nil, fmt.Errorf("blank cookie")
	}

	cookies := make([]string, 0, len(parts))

	for _, s := range parts {
		s = textproto.TrimString(s)

		name, _, _ := strings.Cut(s, "=")
		cookies = append(cookies, name)
	}

	return cookies, nil
}
