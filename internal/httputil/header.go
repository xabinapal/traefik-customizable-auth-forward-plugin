// Package httputil provides HTTP utility functions for header and cookie manipulation.
package httputil

import (
	"net/http"
	"regexp"
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
