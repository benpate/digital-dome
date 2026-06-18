package dome

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/benpate/derp"
	"github.com/benpate/uri"
	"github.com/maypok86/otter"
)

// Some notes on looking up real IP addresses:
// https://adam-p.ca/blog/2022/03/x-forwarded-for/

// TrueHostname returns the "true" hostname for a request, preferring the
// X-Forwarded-Host header (set by proxies) over the request's Host header.
func TrueHostname(request *http.Request) string {

	// If this is a proxied request, we need to use the X-Forwarded-Host header
	// instead of the Host header
	if trueHost := request.Header.Get("X-Forwarded-Host"); trueHost != "" {
		return trueHost
	}

	// Fallback to the Host header if X-Forwarded-Host is not present
	return request.Host
}

// RealIPAddress returns the real IP address of the request,
// taking into account X-Real-IP and X-Forwarded-For headers.
// It is the built-in ClientIPResolver, suitable for passing to New when the
// caller has no trusted-proxy strategy of its own.
func RealIPAddress(request *http.Request) string {

	// Get IP address from CloudFlare (this is more trustworthy than other headers)
	if cfConnectingIP := request.Header.Get("CF-Connecting-IP"); cfConnectingIP != "" {
		return cfConnectingIP
	}

	// Get the "true client ip" for Akamai
	if trueClientIP := request.Header.Get("True-Client-IP"); trueClientIP != "" {
		return trueClientIP
	}

	// Get IP address from X-Forwarded-For header
	if forwardedFor := request.Header.Get("X-Forwarded-For"); forwardedFor != "" {

		// Scan for first non-local ip address
		for _, ip := range strings.Split(forwardedFor, ",") {
			ip = strings.TrimSpace(ip)
			if !uri.IsLocalHostname(ip) {
				return ip
			}
		}
	}

	// Get IP address from X-Real-IP header
	if realIP := request.Header.Get("X-Real-Ip"); realIP != "" {
		return realIP
	}

	// Get IP address from request.RemoteAddr
	result, _, _ := net.SplitHostPort(request.RemoteAddr)
	return result
}

// createCache creates an Otter cache with the provided capacity and variable TTL.
func createCache(capacity int) otter.CacheWithVariableTTL[string, int] {

	// Don't allow negative cache sizes
	if capacity < 0 {
		capacity = 0
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

// sliceContains returns TRUE if the provided slice contains the provided value.
func sliceContains[T comparable](slice []T, value T) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
