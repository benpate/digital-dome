package dome

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/benpate/derp"
	"github.com/stretchr/testify/require"
)

func TestUserAgents(t *testing.T) {

	dome := New(RemoteAddr, BlockKnownBadBots())
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

		// VerifyRequest returns a nil error exactly when the request is allowed.
		err := dome.VerifyRequest(request)
		require.Equal(t, allowed, err == nil)
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

	dome := New(RemoteAddr)
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

	dome := New(RemoteAddr, LogStatusCodes(500))
	t.Cleanup(dome.Close)

	// A custom option supplied to New replaces the corresponding default.
	require.Equal(t, []int{500}, dome.logStatusCodes)
}

func TestNew_NilResolverPanics(t *testing.T) {

	// The clientIP resolver is required; passing nil is a programming error and
	// must panic at construction rather than failing later on the first request.
	require.PanicsWithValue(t, "dome.New: clientIP resolver is required", func() {
		New(nil)
	})
}

func TestNew_RemoteAddrResolver(t *testing.T) {

	// Callers can opt into the built-in lookup by passing RemoteAddr. We confirm
	// it is wired up by blocking the request's TCP peer address.
	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// RemoteAddr uses the host portion of RemoteAddr, so seed that as blocked.
	dome.blockedIPs.Set("1.2.3.4", 6, getTTL(6))

	// A spoofed CF-Connecting-IP header must be ignored by RemoteAddr.
	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	request.Header.Set("CF-Connecting-IP", "5.6.7.8")

	require.NotNil(t, dome.VerifyRequest(request))
}

func TestNew_CustomResolverIsUsed(t *testing.T) {

	// A custom resolver should override the built-in IP lookup entirely. Here
	// the resolver always returns a fixed address, ignoring the request.
	dome := New(func(*http.Request) string {
		return "9.9.9.9"
	})
	t.Cleanup(dome.Close)

	// Block the address the resolver returns (not the request's RemoteAddr).
	dome.blockedIPs.Set("9.9.9.9", 6, getTTL(6))

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	require.NotNil(t, dome.VerifyRequest(request))
}

func TestHandleError_CustomResolverDeterminesBlockedIP(t *testing.T) {

	// HandleError should record blocks against the resolver-supplied address.
	dome := New(func(*http.Request) string {
		return "9.9.9.9"
	})
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	result := dome.HandleError(request, derp.Forbidden("test", "forbidden")) // 403 blocks
	require.Error(t, result)

	count, ok := dome.blockedIPs.Get("9.9.9.9")
	require.True(t, ok)
	require.Equal(t, 1, count)

	// The request's RemoteAddr should NOT have been blocked.
	_, ok = dome.blockedIPs.Get("1.2.3.4")
	require.False(t, ok)
}

/******************************************
 * VerifyRequest
 ******************************************/

func TestVerifyRequest_EmptyUserAgent(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "", "1.2.3.4:5678")
	err := dome.VerifyRequest(request)

	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, derp.ErrorCode(err))
}

func TestVerifyRequest_BlockedPath(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// /wp-admin is in the default BlockedPaths list.
	request := newTestRequest("GET", "/wp-admin", "GoodBrowser", "1.2.3.4:5678")
	err := dome.VerifyRequest(request)

	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, derp.ErrorCode(err))
}

func TestVerifyRequest_AllowedRequest(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// A normal browser requesting a normal path should be allowed.
	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	require.Nil(t, dome.VerifyRequest(request))
}

func TestVerifyRequest_BlockedIPAddress(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// Seed the blocked-IP cache with a count above the threshold of 5.
	dome.blockedIPs.Set("1.2.3.4", 6, getTTL(6))

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	err := dome.VerifyRequest(request)

	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, derp.ErrorCode(err))
}

func TestVerifyRequest_IPBelowThresholdIsAllowed(t *testing.T) {

	dome := New(RemoteAddr)
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
		clientIP:   RemoteAddr,
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

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	require.Nil(t, dome.HandleError(request, nil))
}

func TestHandleError_LogsMatchingStatusCode(t *testing.T) {

	collection := &fakeCollection{}
	dome := New(RemoteAddr, LogDatabase(collection), LogStatusCodes(http.StatusNotFound))
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
	dome := New(RemoteAddr, LogDatabase(collection), LogStatusCodes(http.StatusNotFound))
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
	dome := New(RemoteAddr, LogDatabase(collection), LogStatusCodes(http.StatusNotFound))
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/oops", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Internal("test", "boom") // 500, not in logStatusCodes

	result := dome.HandleError(request, err)
	require.Error(t, result)
	require.Empty(t, collection.saved)
}

func TestHandleError_BlocksOnBlockStatusCode(t *testing.T) {

	dome := New(RemoteAddr) // default blockStatusCodes is {403}
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Forbidden("test", "forbidden") // 403

	result := dome.HandleError(request, err)
	require.Error(t, result)

	// The IP address should now have an error count of 1.
	count, ok := dome.blockedIPs.Get("1.2.3.4")
	require.True(t, ok)
	require.Equal(t, 1, count)
}

func TestHandleError_BlocksOnSoftBlockedPath(t *testing.T) {

	// Use a soft-blocked path with a client (4xx) error that is NOT in
	// blockStatusCodes. This exercises the softBlockedPaths branch.
	dome := New(RemoteAddr,
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
	dome := New(RemoteAddr,
		SoftBlockPaths("/phpunit"),
		BlockStatusCodes(),
	)
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/phpunit", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Internal("test", "boom") // 500

	result := dome.HandleError(request, err)
	require.Error(t, result)

	_, ok := dome.blockedIPs.Get("1.2.3.4")
	require.False(t, ok)
}

func TestHandleError_IncrementsExistingCount(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// Pre-seed an error count, then confirm HandleError increments it.
	dome.blockedIPs.Set("1.2.3.4", 2, getTTL(2))

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Forbidden("test", "forbidden")

	result := dome.HandleError(request, err)
	require.Error(t, result)

	count, ok := dome.blockedIPs.Get("1.2.3.4")
	require.True(t, ok)
	require.Equal(t, 3, count)
}

func TestHandleError_NoBlockForNonMatchingError(t *testing.T) {

	// A 500 error with no soft-blocked path match and no matching block status
	// code should not block the IP address.
	dome := New(RemoteAddr, BlockStatusCodes()) // clear defaults
	t.Cleanup(dome.Close)

	request := newTestRequest("GET", "/welcome", "GoodBrowser", "1.2.3.4:5678")
	err := derp.Internal("test", "boom")

	result := dome.HandleError(request, err)
	require.Error(t, result)

	_, ok := dome.blockedIPs.Get("1.2.3.4")
	require.False(t, ok)
}

/******************************************
 * Close
 ******************************************/

func TestClose(t *testing.T) {

	// Close should not panic.
	dome := New(RemoteAddr)
	require.NotPanics(t, dome.Close)
}
