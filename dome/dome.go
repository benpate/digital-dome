package dome

import (
	"net/http"
	"slices"

	"github.com/benpate/data"
	"github.com/benpate/derp"
	"github.com/cloudflare/ahocorasick"
	"github.com/maypok86/otter"
)

// On advice from Gopher Academy, Silicon Dome uses Aho-Corasick string matching to block user agents.
// https://blog.gopheracademy.com/advent-2014/string-matching/
// https://github.com/cloudflare/ahocorasick

// Dome object contains the matcher that is used to identify blocked user agents.
type Dome struct {
	clientIP          ClientIPResolver
	blockedUserAgents *ahocorasick.Matcher
	blockedPaths      *ahocorasick.Matcher
	softBlockedPaths  *ahocorasick.Matcher
	blockedIPs        otter.CacheWithVariableTTL[string, int]
	logDatabase       data.Collection
	logStatusCodes    []int
	blockStatusCodes  []int
}

// New returns a fully initialized Dome object. The clientIP resolver is REQUIRED
// and is used to determine the "real" IP address of each request. Passing a nil
// resolver is a programming error and causes New to panic.
//
// Callers not behind a trusted proxy can pass the built-in RemoteAddr resolver.
func New(clientIP ClientIPResolver, options ...Option) *Dome {

	if clientIP == nil {
		panic("dome.New: clientIP resolver is required")
	}

	result := Dome{
		clientIP:   clientIP,
		blockedIPs: createCache(1024),
	}

	// Default settings...
	result.With(
		BlockKnownBadBots(),
		BlockPaths(BlockedPaths...),
		SoftBlockPaths(SuspiciousPaths...),
		BlockStatusCodes(http.StatusForbidden),
		LogStatusCodes(http.StatusNotFound),
	)

	// Custom settings...
	result.With(options...)
	return &result
}

// With applies the provided options to the Dome object.
func (dome *Dome) With(options ...Option) {
	for _, option := range options {
		option(dome)
	}
}

// VerifyRequest returns an error if the request should be blocked (a previously
// flagged IP, an empty or blocked User-Agent, or a blocked path), or nil if it is allowed.
func (dome *Dome) VerifyRequest(request *http.Request) error {

	const location = "dome.VerifyRequest"

	// If this IP address has caused more than 5 qualifying errors (since the TTL) then block this request.
	if count, _ := dome.blockedIPs.Get(dome.clientIP(request)); count > 5 {
		return derp.Forbidden(location, "Blocked due to previous scanning activity.  Try again later.", request.RemoteAddr)
	}

	// Try to block request based on the User-Agent
	userAgent := request.Header.Get("User-Agent")

	if userAgent == "" {
		return derp.Forbidden(location, "User Agent must not be empty")
	}

	if dome.blockedUserAgents != nil {
		if dome.blockedUserAgents.Contains([]byte(userAgent)) {
			return derp.Forbidden(location, "User Agent is blocked", userAgent)
		}
	}

	// Try to block request based on the URL/Path
	if dome.blockedPaths != nil {
		if path := request.URL.Path; dome.blockedPaths.Contains([]byte(path)) {
			return derp.Forbidden(location, "Path is blocked", path)
		}
	}

	// This request is ALLOWED.
	return nil
}

// HandleError is called by the HTTP middleware to report an error back into the Dome.
// Based on configureation settings, this will log the error and/or block the IP address.
func (dome *Dome) HandleError(request *http.Request, err error) error {

	const location = "dome.HandleError"

	// If no error, then no error
	if err == nil {
		return nil
	}

	statusCode := derp.ErrorCode(err)

	// Try to add this error to the database log.
	if dome.logDatabase != nil {

		// If this is a status code that we want to log, then log it.
		if slices.Contains(dome.logStatusCodes, statusCode) {

			record := Request{
				UserAgent:  request.Header.Get("User-Agent"),
				IPAddress:  dome.clientIP(request),
				URL:        trueHostname(request) + request.URL.RequestURI(),
				Method:     request.Method,
				StatusCode: statusCode,
				StatusText: http.StatusText(statusCode),
			}

			if saveErr := dome.logDatabase.Save(&record, ""); saveErr != nil {
				derp.Report(derp.Wrap(saveErr, location, "Unable to save log record"))
			}
		}
	}

	block := false

	if slices.Contains(dome.blockStatusCodes, statusCode) {
		block = true

	} else if dome.softBlockedPaths != nil {
		if derp.IsClientError(err) {
			if path := request.URL.Path; dome.softBlockedPaths.Contains([]byte(path)) {
				err = derp.Forbidden(location, "Path is blocked", path, err)
				block = true
			}
		}
	}

	// Try to block this IP address based on the statusCode
	if block {
		remoteAddress := dome.clientIP(request)             // get the real IP address (not some shifty, fake one)
		errorCount, _ := dome.blockedIPs.Get(remoteAddress) // get the existing error count
		errorCount = errorCount + 1                         // increment
		ttl := getTTL(errorCount)                           // calculate the TTL based on the number of errors in the queue
		dome.blockedIPs.Set(remoteAddress, errorCount, ttl) // save the new error count.
	}

	return err
}

// Close releases the resources held by the Dome (its blocked-IP cache).
func (dome *Dome) Close() {
	dome.blockedIPs.Close()
}
