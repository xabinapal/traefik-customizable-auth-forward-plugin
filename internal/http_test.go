package internal_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xabinapal/traefik-customizable-auth-forward-plugin/internal"
)

func TestCopyCookies(t *testing.T) {
	t.Run("filters specified cookies", func(t *testing.T) {
		src := &http.Response{
			Header: http.Header{
				"Set-Cookie": []string{
					"cookie1=value1a",
					"cookie1=value1b",
					"cookie2=value2",
					"cookie3=value3",
				},
			},
		}

		dst := &http.Request{
			Header: http.Header{},
		}

		internal.CopyCookies(src, dst, []string{"cookie1", "cookie2"})

		assert.Equal(t, []string{"cookie1=value1a", "cookie1=value1b", "cookie2=value2"}, dst.Header.Values("Set-Cookie"))
	})

	t.Run("handles nil filter", func(t *testing.T) {
		src := &http.Response{
			Header: http.Header{
				"Set-Cookie": []string{
					"cookie1=value1",
					"cookie2=value2",
				},
			},
		}

		dst := &http.Request{
			Header: http.Header{},
		}

		internal.CopyCookies(src, dst, nil)

		assert.Empty(t, dst.Header.Values("Set-Cookie"))
	})

	t.Run("handles empty filter", func(t *testing.T) {
		src := &http.Response{
			Header: http.Header{
				"Set-Cookie": []string{
					"cookie1=value1",
					"cookie2=value2",
				},
			},
		}

		dst := &http.Request{
			Header: http.Header{},
		}

		internal.CopyCookies(src, dst, []string{})

		assert.Empty(t, dst.Header.Values("Set-Cookie"))
	})

	t.Run("handles no cookies in source", func(t *testing.T) {
		src := &http.Response{
			Header: http.Header{},
		}

		dst := &http.Request{
			Header: http.Header{},
		}

		internal.CopyCookies(src, dst, []string{"cookie1", "cookie2"})

		assert.Empty(t, dst.Header.Values("Set-Cookie"))
	})

	t.Run("handles non-matching filter", func(t *testing.T) {
		src := &http.Response{
			Header: http.Header{
				"Set-Cookie": []string{
					"cookie1=value1",
					"cookie2=value2",
				},
			},
		}

		dst := &http.Request{
			Header: http.Header{},
		}

		internal.CopyCookies(src, dst, []string{"cookie3", "cookie4"})

		assert.Empty(t, dst.Header.Values("Set-Cookie"))
	})
}
