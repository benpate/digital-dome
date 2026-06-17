package dome

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/benpate/derp"
	"github.com/stretchr/testify/require"
)

func TestUserAgents(t *testing.T) {

	dome := New(BlockKnownBadBots())
	t.Cleanup(dome.Close)

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

/******************************************
 * New
 ******************************************/

func TestNew_Defaults(t *testing.T) {

	dome := New()
	t.Cleanup(dome.Close)

	// New installs a default set of matchers and status codes.
	require.NotNil(t, dome.blockedUserAgents)
	require.NotNil(t, dome.blockedPaths)
	require.NotNil(t, dome.softBlockedPaths)
	require.Equal(t, []int{http.StatusForbidden}, dome.blockStatusCodes)
	require.Equal(t, []int{http.StatusNotFound}, dome.logStatusCodes)
	require.Equal(t, 1024, dome.blockedIPs.Capacity())
}

func TestNew_CustomOptionsOverrideDefaults(t *testing.T) {

	dome := New(LogStatusCodes(500))
	t.Cleanup(dome.Close)

	// A custom option supplied to New replaces the corresponding default.
	require.Equal(t, []int{500}, dome.logStatusCodes)
}

/******************************************
 * VerifyRequest
 ******************************************/

func TestVerifyRequest_EmptyUserAgent(t *testing.T) {

	dome := New()
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "", "1.2.3.4:5678")
	err := dome.VerifyRequest(request)

	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, derp.ErrorCode(err))
}

func TestVerifyRequest_BlockedPath(t *testing.T) {

	dome := New()
	t.Cleanup(dome.Close)

	// /wp-admin is in the default BlockedPaths list.
	request := newTestRequest("GET", "/wp-admin", "GoodBrowser", "1.2.3.4:5678")
	err := dome.VerifyRequest(request)

	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, derp.ErrorCode(err))
}

func TestVerifyRequest_AllowedRequest(t *testing.T) {

	dome := New()
	t.Cleanup(dome.Close)

	// A normal browser requesting a normal path should be allowed.
	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	require.Nil(t, dome.VerifyRequest(request))
}

func TestVerifyRequest_BlockedIPAddress(t *testing.T) {

	dome := New()
	t.Cleanup(dome.Close)

	// Seed the blocked-IP cache with a count above the threshold of 5.
	dome.blockedIPs.Set("1.2.3.4", 6, getTTL(6))

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	err := dome.VerifyRequest(request)

	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, derp.ErrorCode(err))
}

func TestVerifyRequest_IPBelowThresholdIsAllowed(t *testing.T) {

	dome := New()
	t.Cleanup(dome.Close)

	// A count of exactly 5 is NOT over the threshold (the check is > 5).
	dome.blockedIPs.Set("1.2.3.4", 5, getTTL(5))

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	require.Nil(t, dome.VerifyRequest(request))
}

func TestVerifyRequest_NilMatchers(t *testing.T) {

	// A Dome with no user-agent or path matchers configured should still run
	// VerifyRequest without panicking and allow a non-empty user agent.
	dome := Dome{
		blockedIPs: createCache(16),
	}
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/anything", "AnyAgent", "1.2.3.4:5678")
	require.Nil(t, dome.VerifyRequest(request))
}

/******************************************
 * HandleError
 ******************************************/

func TestHandleError_NilError(t *testing.T) {

	dome := New()
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	require.Nil(t, dome.HandleError(request, nil))
}

func TestHandleError_LogsMatchingStatusCode(t *testing.T) {

	collection := &fakeCollection{}
	dome := New(LogDatabase(collection), LogStatusCodes(http.StatusNotFound))
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/missing", "GoodBrowser", "1.2.3.4:5678")
	err := derp.NotFound("test", "not found")

	result := dome.HandleError(request, err)

	require.NotNil(t, result)
	require.Len(t, collection.saved, 1)

	// Confirm the logged record captured the request details.
	record := collection.saved[0].(*Request)
	require.Equal(t, "GoodBrowser", record.UserAgent)
	require.Equal(t, "1.2.3.4", record.IPAddress)
	require.Equal(t, "GET", record.Method)
	require.Equal(t, http.StatusNotFound, record.StatusCode)
	require.Equal(t, "Not Found", record.StatusText)
}

func TestHandleError_SaveFailureIsReported(t *testing.T) {

	// When the log database returns an error from Save, HandleError should
	// report it internally (via derp.Report) but still return the original
	// error to the caller rather than the save error.
	collection := &fakeCollection{saveErr: derp.Internal("db", "write failed")}
	dome := New(LogDatabase(collection), LogStatusCodes(http.StatusNotFound))
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/missing", "GoodBrowser", "1.2.3.4:5678")
	err := derp.NotFound("test", "not found")

	result := dome.HandleError(request, err)

	// The returned error is the original request error, not the save error.
	require.NotNil(t, result)
	require.Equal(t, http.StatusNotFound, derp.ErrorCode(result))
	require.Empty(t, collection.saved)
}

func TestHandleError_DoesNotLogUnmatchedStatusCode(t *testing.T) {

	collection := &fakeCollection{}
	dome := New(LogDatabase(collection), LogStatusCodes(http.StatusNotFound))
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/oops", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Internal("test", "boom") // 500, not in logStatusCodes

	dome.HandleError(request, err)
	require.Empty(t, collection.saved)
}

func TestHandleError_BlocksOnBlockStatusCode(t *testing.T) {

	dome := New() // default blockStatusCodes is {403}
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Forbidden("test", "forbidden") // 403

	dome.HandleError(request, err)

	// The IP address should now have an error count of 1.
	count, ok := dome.blockedIPs.Get("1.2.3.4")
	require.True(t, ok)
	require.Equal(t, 1, count)
}

func TestHandleError_BlocksOnSoftBlockedPath(t *testing.T) {

	// Use a soft-blocked path with a client (4xx) error that is NOT in
	// blockStatusCodes. This exercises the softBlockedPaths branch.
	dome := New(
		SoftBlockPaths("/phpunit"),
		BlockStatusCodes(), // clear defaults so only the soft-block path triggers
	)
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/phpunit", "GoodBrowser", "1.2.3.4:5678")
	err := derp.NotFound("test", "not found") // 404 is a client error

	result := dome.HandleError(request, err)

	require.NotNil(t, result)
	// The error should have been wrapped into a Forbidden error.
	require.Equal(t, http.StatusForbidden, derp.ErrorCode(result))

	count, ok := dome.blockedIPs.Get("1.2.3.4")
	require.True(t, ok)
	require.Equal(t, 1, count)
}

func TestHandleError_SoftBlockedPathServerErrorDoesNotBlock(t *testing.T) {

	// A server (5xx) error on a soft-blocked path is NOT a client error, so it
	// should not trigger a block.
	dome := New(
		SoftBlockPaths("/phpunit"),
		BlockStatusCodes(),
	)
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/phpunit", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Internal("test", "boom") // 500

	dome.HandleError(request, err)

	_, ok := dome.blockedIPs.Get("1.2.3.4")
	require.False(t, ok)
}

func TestHandleError_IncrementsExistingCount(t *testing.T) {

	dome := New()
	t.Cleanup(dome.Close)

	// Pre-seed an error count, then confirm HandleError increments it.
	dome.blockedIPs.Set("1.2.3.4", 2, getTTL(2))

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Forbidden("test", "forbidden")

	dome.HandleError(request, err)

	count, ok := dome.blockedIPs.Get("1.2.3.4")
	require.True(t, ok)
	require.Equal(t, 3, count)
}

func TestHandleError_NoBlockForNonMatchingError(t *testing.T) {

	// A 500 error with no soft-blocked path match and no matching block status
	// code should not block the IP address.
	dome := New(BlockStatusCodes()) // clear defaults
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Internal("test", "boom")

	dome.HandleError(request, err)

	_, ok := dome.blockedIPs.Get("1.2.3.4")
	require.False(t, ok)
}

/******************************************
 * Close
 ******************************************/

func TestClose(t *testing.T) {

	// Close should not panic and should leave the cache safe to query.
	dome := New()
	dome.Close()
}
