package httputil

import (
	"net/http"
	"slices"
)

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
