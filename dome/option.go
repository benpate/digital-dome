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

// BlockAllBadBots is a dome.Option that blocks all known bad bots.
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

// SoftBlockpaths is a dome.Option that soft blocks the provided paths.
// This means that the requests are allowed, but will count towards a
// client's score if the request returns a 404 error.
func SoftBlockPaths(paths ...string) Option {
	return func(d *Dome) {
		d.softBlockedPaths = ahocorasick.NewStringMatcher(paths)
	}
}

// BlockPaths is a dome.Option that blocks the provided paths.
// These requests are blocked from the application server, and will
// count towards a client's score.
func BlockPaths(paths ...string) Option {
	return func(d *Dome) {
		d.blockedPaths = ahocorasick.NewStringMatcher(paths)
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

// BlockStatusCodes configures Dome to log requests with specific error codes
func BlockStatusCodes(statusCodes ...int) Option {
	return func(d *Dome) {
		d.blockStatusCodes = statusCodes
	}
}

// BlockCache is a dome.Option that initializes a new cache for blocked IP addresses
func BlockCache(capacity int) Option {
	return func(d *Dome) {

		// If the capacity has not changed, then do nothing.
		if capacity == d.blockedIPs.Capacity() {
			return
		}

		// Close the previous cache, if it exists
		d.blockedIPs.Close()

		// Create a new cache with the new capacity
		d.blockedIPs = createCache(capacity)
	}
}
