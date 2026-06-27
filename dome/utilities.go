package dome

import (
	"net"
	"net/http"
	"time"

	"github.com/benpate/derp"
	"github.com/maypok86/otter"
)

// trueHostname returns the "true" hostname for a request, preferring the
// X-Forwarded-Host header (set by proxies) over the request's Host header.
func trueHostname(request *http.Request) string {

	// Trust the client-supplied X-Forwarded-Host header here because trueHostname
	// only feeds the URL of a log record -- never a blocking decision -- so a
	// spoofed value cannot bypass any guard.
	if trueHost := request.Header.Get("X-Forwarded-Host"); trueHost != "" {
		return trueHost
	}

	// Fallback to the Host header if X-Forwarded-Host is not present
	return request.Host
}

// RemoteAddr returns the request's TCP peer address (host portion of
// RemoteAddr). It is the built-in ClientIPResolver and the safe default when
// Dome is not behind a trusted proxy, because it cannot be spoofed by request
// headers. Callers behind a proxy should inject a proxy-aware resolver instead.
func RemoteAddr(request *http.Request) string {
	host, _, _ := net.SplitHostPort(request.RemoteAddr)
	return host
}

// createCache creates an Otter cache with the provided capacity and variable TTL.
func createCache(capacity int) otter.CacheWithVariableTTL[string, int] {

	// Don't allow zero or negative cache sizes. The underlying otter builder
	// panics when asked to build a cache with a capacity less than 1, so clamp
	// any such value up to a minimum of 1.
	if capacity < 1 {
		capacity = 1
	}

	// Create a new cache with the correct capacity
	builder, err := otter.NewBuilder[string, int](capacity)
	derp.Report(err)

	result, err := builder.WithVariableTTL().Build()
	derp.Report(err)

	return result
}

// getTTL returns a time.Duration to keep an IP address record, based
// on the number of errors it has received
func getTTL(count int) time.Duration {

	switch {
	// For the first ten errors, wait one minute each (up to ten minutes)
	// Requests will start being blocked after 5 errors / 5 minutes
	case count < 10:
		return 1 * time.Minute

	// Increase linearly from 10 to 60 errors (up to two hours per request)
	case count < 60:
		return time.Duration(2*count) * time.Minute

	default:
		return 2 * time.Hour
	}
}
