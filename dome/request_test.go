package dome

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequest_ID(t *testing.T) {

	// Request.ID always returns the empty string (these records are
	// write-only log entries and are never looked up by ID).
	request := Request{
		UserAgent:  "EvilBot",
		IPAddress:  "1.2.3.4",
		URL:        "example.com/wp-admin",
		Method:     "GET",
		StatusCode: 403,
		StatusText: "Forbidden",
	}

	require.Equal(t, "", request.ID())
}

func TestRequest_IsNew(t *testing.T) {

	// A freshly constructed Request embeds an empty journal.Journal, so it
	// should report itself as new (not yet saved).
	request := Request{}
	require.True(t, request.IsNew())
}
