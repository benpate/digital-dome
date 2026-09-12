package dome

import (
	"github.com/benpate/data"
	"github.com/cloudflare/ahocorasick"
)

// Option is a functional argument that configures a Dome object.
type Option func(*Dome)

/******************************************
 * Blocking Known User Agents
 ******************************************/

// BlockKnownAIBots is a dome.Option that blocks known AI crawlers.
func BlockKnownAIBots() Option {
	return BlockUserAgents(KnownAIBots...)
}

// BlockKnownBadBots is a dome.Option that blocks all known bad bots.
func BlockKnownBadBots() Option {
	return BlockUserAgents(AllKnownBadBots...)
}

// BlockUserAgents is a dome.Option that blocks the provided user agents.
func BlockUserAgents(blockedAgents ...string) Option {
	return func(d *Dome) {
		d.blockedUserAgents = ahocorasick.NewStringMatcher(blockedAgents)
	}
}

/******************************************
 * Blocking Known Paths
 ******************************************/

// SoftBlockPaths is a dome.Option that soft blocks the provided paths.
func SoftBlockPaths(paths ...string) Option {
	return func(d *Dome) {

		// Soft-blocked requests are allowed through, but count against the client's
		// score if the request returns a client (4xx) error.
		d.softBlockedPaths = ahocorasick.NewStringMatcher(paths)
	}
}

// BlockPaths is a dome.Option that blocks the provided paths.
func BlockPaths(paths ...string) Option {
	return func(d *Dome) {

		// These requests never reach the application server, and count against the client's score.
		d.blockedPaths = ahocorasick.NewStringMatcher(paths)
	}
}

/******************************************
 * Blocking Known Query Parameters
 ******************************************/

// BlockQueryParams is a dome.Option that blocks requests carrying any of the
// provided query parameter names, regardless of the path they are sent to.
func BlockQueryParams(names ...string) Option {
	return func(d *Dome) {

		// Matched by NAME, and exactly, unlike every other list here. A query VALUE is
		// attacker-controlled, so a substring rule over values fires on ordinary traffic --
		// any link preview or oEmbed lookup whose target URL merely mentions the pattern.
		d.blockedQueryParams = names
	}
}

/******************************************
 * Log Handling
 ******************************************/

// LogStatusCodes configures Dome to log requests with specific error codes
func LogStatusCodes(statusCodes ...int) Option {
	return func(d *Dome) {
		d.logStatusCodes = statusCodes
	}
}

// LogDatabase is a dome.Option that configures the collection where failed requests will be logged
func LogDatabase(collection data.Collection) Option {
	return func(d *Dome) {
		d.logDatabase = collection
	}
}

/******************************************
 * Block Handling
 ******************************************/

// BlockStatusCodes configures Dome to block requests with specific error codes
func BlockStatusCodes(statusCodes ...int) Option {
	return func(d *Dome) {
		d.blockStatusCodes = statusCodes
	}
}

// BlockCache is a dome.Option that initializes a new cache for blocked IP addresses
func BlockCache(capacity int) Option {
	return func(d *Dome) {

		// RULE: If the capacity has not changed, then do nothing
		if capacity == d.blockedIPs.Capacity() {
			return
		}

		// Close the previous cache, releasing its resources
		d.blockedIPs.Close()

		// Create a new cache with the new capacity
		d.blockedIPs = createCache(capacity)
	}
}
