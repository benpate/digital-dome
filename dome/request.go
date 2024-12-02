package dome

import (
	"github.com/benpate/data/journal"
)

type Request struct {
	UserAgent  string `bson:"userAgent"`
	IPAddress  string `bson:"ipAddress"`
	URL        string `bson:"url"`
	Method     string `bson:"method"`
	StatusCode int    `bson:"statusCode"`
	StatusText string `bson:"statusText"`
	Error      error  `bson:"error"`
	journal.Journal
}

func (request Request) ID() string {
	return ""
}
