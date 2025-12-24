package dome

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserAgents(t *testing.T) {

	dome := New(BlockKnownBadBots())

	verify := func(userAgent string, allowed bool) {

		requestURL, _ := url.Parse("http://example.com/some-valid-path")
		request := &http.Request{
			Host: "example.com",
			URL:  requestURL,
			Header: http.Header{
				"User-Agent": []string{userAgent},
			},
		}

		result := dome.VerifyRequest(request) // nolint:scopeguard

		if allowed {
			require.Nil(t, result)
		} else {
			require.NotNil(t, result)
		}
	}

	verify("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Safari/605.1.15", true)
	verify("Mozilla 5.0 / Whatever", true)
	verify("Applebot-Extended", false)
	verify("ClaudeBot", false)
}
