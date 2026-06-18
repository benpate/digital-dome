package dome

import (
	"github.com/benpate/data/journal"
)

// Request is a log record describing an HTTP request that Dome flagged,
// suitable for writing to a LogDatabase collection.
type Request struct {
	UserAgent  string `bson:"userAgent"`
	IPAddress  string `bson:"ipAddress"`
	URL        string `bson:"url"`
	Method     string `bson:"method"`
	StatusCode int    `bson:"statusCode"`
	StatusText string `bson:"statusText"`

	journal.Journal `bson:",inline"`
}

// ID satisfies the data.Object interface. It always returns an empty string
// because Request records are write-only and never looked up by ID.
func (request Request) ID() string {
	return ""
}
