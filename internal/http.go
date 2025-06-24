package internal

import (
	"net/http"
	"regexp"
	"slices"
)

func CopyHeaders(src http.Header, dst http.Header, filter []string) {
	if len(filter) == 0 {
		return
	}

	for _, header := range filter {
		if values := src.Values(header); len(values) > 0 {
			for _, value := range values {
				dst.Add(header, value)
			}
		}
	}
}

func CopyHeadersRegex(src http.Header, dst http.Header, regex *regexp.Regexp) {
	if regex == nil {
		return
	}

	for headerKey, headerValues := range src {
		if regex.MatchString(headerKey) {
			for _, value := range headerValues {
				dst.Add(headerKey, value)
			}
		}
	}
}

type Cookier interface {
	Cookies() []*http.Cookie
}

type CookieAdder interface {
	AddCookie(cookie *http.Cookie)
}

func CopyCookies(src Cookier, dst CookieAdder, filter []string) {
	if len(filter) == 0 {
		return
	}

	cookies := src.Cookies()

	for _, cookie := range cookies {
		if slices.Contains(filter, cookie.Name) {
			dst.AddCookie(cookie)
		}
	}
}
