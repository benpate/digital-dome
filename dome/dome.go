package dome

import (
	"hash/fnv"
	"net/http"
	"slices"
	"sync"

	"github.com/benpate/data"
	"github.com/benpate/derp"
	"github.com/cloudflare/ahocorasick"
	"github.com/maypok86/otter"
)

// On advice from Gopher Academy, Digital Dome uses Aho-Corasick string matching to block user agents.
// https://blog.gopheracademy.com/advent-2014/string-matching/
// https://github.com/cloudflare/ahocorasick

// blockCountShards is the number of mutexes that guard the blocked-IP counter.
// Each IP maps to one shard, so updates to different IPs rarely contend.
const blockCountShards = 256

// Dome object contains the matcher that is used to identify blocked user agents.
type Dome struct {
	clientIP          ClientIPResolver
	blockedUserAgents *ahocorasick.Matcher
	blockedPaths      *ahocorasick.Matcher
	softBlockedPaths  *ahocorasick.Matcher
	blockedIPs        otter.CacheWithVariableTTL[string, int]
	blockCountLocks   [blockCountShards]sync.Mutex
	logDatabase       data.Collection
	logStatusCodes    []int
	blockStatusCodes  []int
}

// New returns a fully initialized Dome object, using clientIP to resolve the
// "real" IP address of each request.
func New(clientIP ClientIPResolver, options ...Option) *Dome {

	// RULE: A resolver is required. Passing nil is a programming error, not a runtime condition.
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

	// Mutates matchers and cache without synchronization, so it must run during setup.
	// Calling it once requests are in flight races with VerifyRequest and HandleError.

	for _, option := range options {
		option(dome)
	}
}

// VerifyRequest returns an error if the request should be blocked (a previously
// flagged IP, an empty or blocked User-Agent, or a blocked path), or nil if it is allowed.
func (dome *Dome) VerifyRequest(request *http.Request) error {

	const location = "dome.VerifyRequest"

	// RULE: Block IP addresses that have already exceeded the error threshold (within the TTL)
	if count, _ := dome.blockedIPs.Get(dome.clientIP(request)); count > 5 {
		return derp.Forbidden(location, "Blocked due to previous scanning activity.  Try again later.", request.RemoteAddr)
	}

	// RULE: Every request must identify itself with a User-Agent
	userAgent := request.Header.Get("User-Agent")

	if userAgent == "" {
		return derp.Forbidden(location, "User Agent must not be empty")
	}

	// RULE: Block User-Agents that match the blocklist
	if dome.blockedUserAgents != nil {
		if dome.blockedUserAgents.Contains([]byte(userAgent)) {
			return derp.Forbidden(location, "User Agent is blocked", userAgent)
		}
	}

	// RULE: Block paths that match the blocklist
	if dome.blockedPaths != nil {
		if path := request.URL.Path; dome.blockedPaths.Contains([]byte(path)) {
			return derp.Forbidden(location, "Path is blocked", path)
		}
	}

	// This request is ALLOWED.
	return nil
}

// HandleError reports a downstream error back into the Dome, which may log the
// error and/or count it against the client's IP address.
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

	// RULE: A blockable status code, or a client error on a soft-blocked path, counts against the client
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
		dome.incrementBlockCount(dome.clientIP(request)) // get the real IP (not some shifty, fake one) and count the error
	}

	return err
}

// Block records one abuse event against the request's client IP, pushing that IP
// toward (and refreshing the TTL of) a temporary block.
func (dome *Dome) Block(request *http.Request) {

	// Feeds the Dome from application policy that never surfaces as a blockable HTTP
	// status -- a failed sign-in that renders its own response, for example. Keys on the
	// same resolved IP as VerifyRequest, so enough calls block the client's whole traffic.

	dome.incrementBlockCount(dome.clientIP(request))
}

// incrementBlockCount adds one to the error count for the given IP address and
// refreshes its TTL.
func (dome *Dome) incrementBlockCount(remoteAddress string) {

	// Otter exposes no atomic update, so a shard lock makes the read-modify-write atomic.
	// Without it, concurrent errors from one IP lose increments -- the exact burst this catches.

	// Lock the shard this IP maps to
	lock := &dome.blockCountLocks[blockCountShard(remoteAddress)]
	lock.Lock()
	defer lock.Unlock()

	errorCount, _ := dome.blockedIPs.Get(remoteAddress) // get the existing error count
	errorCount = errorCount + 1                         // increment
	ttl := getTTL(errorCount)                           // calculate the TTL based on the number of errors in the queue
	dome.blockedIPs.Set(remoteAddress, errorCount, ttl) // save the new error count
}

// blockCountShard maps an IP address to one of the blockCountLocks shards.
func blockCountShard(remoteAddress string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(remoteAddress)) // hash.Write never returns an error
	return hash.Sum32() % blockCountShards
}

// Close releases the resources held by the Dome (its blocked-IP cache).
func (dome *Dome) Close() {
	dome.blockedIPs.Close()
}
