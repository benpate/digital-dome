package dome

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/******************************************
 * RemoteAddr
 ******************************************/

func TestRemoteAddr(t *testing.T) {

	// RemoteAddr returns the host portion of the request's RemoteAddr.
	request := &http.Request{RemoteAddr: "10.0.0.1:1234"}
	assert.Equal(t, "10.0.0.1", RemoteAddr(request))
}

func TestRemoteAddr_IgnoresHeaders(t *testing.T) {

	// RemoteAddr must NOT trust client-supplied headers; only the real TCP peer
	// counts. This is the security property that makes it spoof-proof.
	request := &http.Request{
		RemoteAddr: "10.0.0.1:1234",
		Header:     http.Header{},
	}
	request.Header.Set("CF-Connecting-IP", "1.1.1.1")
	request.Header.Set("X-Forwarded-For", "2.2.2.2")
	request.Header.Set("X-Real-Ip", "3.3.3.3")

	assert.Equal(t, "10.0.0.1", RemoteAddr(request))
}

func TestRemoteAddr_BadRemoteAddr(t *testing.T) {

	// A RemoteAddr without a port cannot be split, so SplitHostPort fails and
	// RemoteAddr returns the empty string.
	request := &http.Request{RemoteAddr: "not-a-valid-host-port"}
	assert.Equal(t, "", RemoteAddr(request))
}

// FuzzRemoteAddr confirms that RemoteAddr never panics, regardless of the
// RemoteAddr value it is given.
func FuzzRemoteAddr(f *testing.F) {

	f.Add("6.6.6.6:7777")
	f.Add("")
	f.Add("bad-remote-addr")
	f.Add("[::1]:80")

	f.Fuzz(func(_ *testing.T, remoteAddr string) {
		request := &http.Request{RemoteAddr: remoteAddr}

		// We only require that the call returns without panicking.
		_ = RemoteAddr(request)
	})
}

/******************************************
 * trueHostname
 ******************************************/

func TestTrueHostname(t *testing.T) {

	// X-Forwarded-Host (set by a proxy) takes priority over the Host field.
	request := &http.Request{
		Host:   "internal.example.com",
		Header: http.Header{},
	}
	request.Header.Set("X-Forwarded-Host", "public.example.com")
	assert.Equal(t, "public.example.com", trueHostname(request))
}

func TestTrueHostname_FallsBackToHost(t *testing.T) {

	// When X-Forwarded-Host is absent, the Host field is used.
	request := &http.Request{
		Host:   "example.com",
		Header: http.Header{},
	}
	assert.Equal(t, "example.com", trueHostname(request))
}

/******************************************
 * createCache
 ******************************************/

func TestCreateCache(t *testing.T) {

	cache := createCache(16)
	t.Cleanup(cache.Close)

	require.Equal(t, 16, cache.Capacity())
}

// The underlying otter builder panics when asked to build a cache with a
// capacity less than 1, so createCache clamps zero and negative values up to a
// minimum of 1. These tests deliberately pass invalid capacities to prove that
// createCache does not panic and returns a usable cache.
func TestCreateCache_ZeroCapacity(t *testing.T) {

	cache := createCache(0)
	t.Cleanup(cache.Close)

	require.Equal(t, 1, cache.Capacity())
}

func TestCreateCache_NegativeCapacity(t *testing.T) {

	cache := createCache(-100)
	t.Cleanup(cache.Close)

	require.Equal(t, 1, cache.Capacity())
}

func TestBlockCache_ZeroCapacityDoesNotPanic(t *testing.T) {

	// Exercise the public path: a caller passing BlockCache(0) must not panic.
	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	require.NotPanics(t, func() {
		dome.With(BlockCache(0))
	})
	require.Equal(t, 1, dome.blockedIPs.Capacity())
}

/******************************************
 * getTTL
 ******************************************/

func TestGetTTL(t *testing.T) {

	// Closure confirms the TTL returned for a given error count.
	verify := func(count int, expected time.Duration) {
		assert.Equal(t, expected, getTTL(count))
	}

	// For the first ten errors, the TTL is a flat one minute.
	verify(0, 1*time.Minute)
	verify(1, 1*time.Minute)
	verify(9, 1*time.Minute)

	// From 10 to 59 errors, the TTL grows linearly at 2 minutes per error.
	verify(10, 20*time.Minute)
	verify(30, 60*time.Minute)
	verify(59, 118*time.Minute)

	// At 60 errors and beyond, the TTL is capped at two hours.
	verify(60, 2*time.Hour)
	verify(1000, 2*time.Hour)
}
