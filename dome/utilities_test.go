package dome

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/******************************************
 * RealIPAddress
 ******************************************/

func TestRealIPAddress(t *testing.T) {

	// Closure builds a request with the provided headers and remote address,
	// then confirms that RealIPAddress returns the expected value.
	verify := func(remoteAddr string, headers map[string]string, expected string) {
		request := &http.Request{
			RemoteAddr: remoteAddr,
			Header:     http.Header{},
		}

		for key, value := range headers {
			request.Header.Set(key, value)
		}

		assert.Equal(t, expected, RealIPAddress(request))
	}

	// CF-Connecting-IP has the highest priority.
	verify("10.0.0.1:1234", map[string]string{
		"CF-Connecting-IP": "1.1.1.1",
		"True-Client-IP":   "2.2.2.2",
		"X-Forwarded-For":  "3.3.3.3",
		"X-Real-Ip":        "4.4.4.4",
	}, "1.1.1.1")

	// True-Client-IP is used when CF-Connecting-IP is absent.
	verify("10.0.0.1:1234", map[string]string{
		"True-Client-IP":  "2.2.2.2",
		"X-Forwarded-For": "3.3.3.3",
		"X-Real-Ip":       "4.4.4.4",
	}, "2.2.2.2")

	// X-Forwarded-For is used when the higher-priority headers are absent.
	verify("10.0.0.1:1234", map[string]string{
		"X-Forwarded-For": "3.3.3.3",
		"X-Real-Ip":       "4.4.4.4",
	}, "3.3.3.3")

	// X-Real-Ip is used when only it and RemoteAddr are present.
	verify("10.0.0.1:1234", map[string]string{
		"X-Real-Ip": "4.4.4.4",
	}, "4.4.4.4")

	// RemoteAddr (host portion only) is the final fallback.
	verify("10.0.0.1:1234", map[string]string{}, "10.0.0.1")
}

func TestRealIPAddress_ForwardedForSkipsLocalhost(t *testing.T) {

	// The first non-localhost address in X-Forwarded-For should be returned.
	request := &http.Request{
		RemoteAddr: "10.0.0.1:1234",
		Header:     http.Header{},
	}
	request.Header.Set("X-Forwarded-For", "127.0.0.1, 192.168.1.1, 8.8.8.8")

	assert.Equal(t, "8.8.8.8", RealIPAddress(request))
}

func TestRealIPAddress_ForwardedForAllLocalhost(t *testing.T) {

	// When every X-Forwarded-For entry is recognized as localhost/private, the
	// loop falls through and the next available source (X-Real-Ip here) is used.
	// uri.IsLocalHostname recognizes IPv4 loopback/RFC-1918 ranges as well as
	// IPv6 loopback (::1) and RFC-4193 unique-local addresses.
	request := &http.Request{
		RemoteAddr: "10.0.0.1:1234",
		Header:     http.Header{},
	}
	request.Header.Set("X-Forwarded-For", "127.0.0.1, ::1, 10.0.0.5, 192.168.1.1")
	request.Header.Set("X-Real-Ip", "9.9.9.9")

	assert.Equal(t, "9.9.9.9", RealIPAddress(request))
}

func TestRealIPAddress_BadRemoteAddr(t *testing.T) {

	// A RemoteAddr without a port cannot be split, so SplitHostPort fails and
	// RealIPAddress returns the empty string.
	request := &http.Request{
		RemoteAddr: "not-a-valid-host-port",
		Header:     http.Header{},
	}

	assert.Equal(t, "", RealIPAddress(request))
}

// FuzzRealIPAddress confirms that RealIPAddress never panics, regardless of the
// (untrusted) header and remote-address values it is given. It parses attacker-
// controlled input, so robustness against malformed values matters.
func FuzzRealIPAddress(f *testing.F) {

	f.Add("1.1.1.1", "2.2.2.2", "3.3.3.3, 4.4.4.4", "5.5.5.5", "6.6.6.6:7777")
	f.Add("", "", "", "", "")
	f.Add("", "", "127.0.0.1, , 8.8.8.8", "", "bad-remote-addr")

	f.Fuzz(func(t *testing.T, cfIP string, trueIP string, forwardedFor string, realIP string, remoteAddr string) {

		request := &http.Request{
			RemoteAddr: remoteAddr,
			Header:     http.Header{},
		}
		request.Header.Set("CF-Connecting-IP", cfIP)
		request.Header.Set("True-Client-IP", trueIP)
		request.Header.Set("X-Forwarded-For", forwardedFor)
		request.Header.Set("X-Real-Ip", realIP)

		// We only require that the call returns without panicking.
		_ = RealIPAddress(request)
	})
}

/******************************************
 * TrueHostname
 ******************************************/

func TestTrueHostname(t *testing.T) {

	// X-Forwarded-Host (set by a proxy) takes priority over the Host field.
	request := &http.Request{
		Host:   "internal.example.com",
		Header: http.Header{},
	}
	request.Header.Set("X-Forwarded-Host", "public.example.com")
	assert.Equal(t, "public.example.com", TrueHostname(request))
}

func TestTrueHostname_FallsBackToHost(t *testing.T) {

	// When X-Forwarded-Host is absent, the Host field is used.
	request := &http.Request{
		Host:   "example.com",
		Header: http.Header{},
	}
	assert.Equal(t, "example.com", TrueHostname(request))
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
	dome := New(RealIPAddress)
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

/******************************************
 * sliceContains
 ******************************************/

func TestSliceContains(t *testing.T) {

	assert.True(t, sliceContains([]int{1, 2, 3}, 2))
	assert.True(t, sliceContains([]int{1, 2, 3}, 1))
	assert.True(t, sliceContains([]int{1, 2, 3}, 3))

	assert.False(t, sliceContains([]int{1, 2, 3}, 4))
	assert.False(t, sliceContains([]int{}, 1))
	assert.False(t, sliceContains(nil, 1))

	// sliceContains is generic, so confirm it works with strings too.
	assert.True(t, sliceContains([]string{"a", "b"}, "b"))
	assert.False(t, sliceContains([]string{"a", "b"}, "c"))
}
