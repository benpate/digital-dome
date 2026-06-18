package dome

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/benpate/data"
	"github.com/benpate/data/option"
	"github.com/benpate/exp"
	"github.com/stretchr/testify/require"
)

/******************************************
 * Test Fake: data.Collection
 ******************************************/

// fakeCollection is a minimal in-memory implementation of data.Collection that
// records every object passed to Save. It lets us assert on logging behavior
// without pulling in a real (or mock) database dependency.
type fakeCollection struct {
	saved   []data.Object
	saveErr error // when set, Save returns this error instead of recording
}

func (c *fakeCollection) Context() context.Context { return context.Background() }

func (c *fakeCollection) Count(exp.Expression, ...option.Option) (int64, error) {
	return int64(len(c.saved)), nil
}

func (c *fakeCollection) Save(object data.Object, _ string) error {
	if c.saveErr != nil {
		return c.saveErr
	}
	c.saved = append(c.saved, object)
	return nil
}

func (c *fakeCollection) Query(any, exp.Expression, ...option.Option) error        { return nil }
func (c *fakeCollection) Load(exp.Expression, data.Object, ...option.Option) error { return nil }
func (c *fakeCollection) Delete(data.Object, string) error                         { return nil }
func (c *fakeCollection) HardDelete(exp.Expression) error                          { return nil }

func (c *fakeCollection) Iterator(exp.Expression, ...option.Option) (data.Iterator, error) {
	return nil, nil
}

/******************************************
 * Block User Agent Options
 ******************************************/

func TestBlockUserAgents(t *testing.T) {

	dome := New(RemoteAddr, BlockUserAgents("EvilBot", "BadCrawler"))
	t.Cleanup(dome.Close)

	require.NotNil(t, dome.blockedUserAgents)
	require.True(t, dome.blockedUserAgents.Contains([]byte("EvilBot")))
	require.True(t, dome.blockedUserAgents.Contains([]byte("BadCrawler")))
	require.False(t, dome.blockedUserAgents.Contains([]byte("FriendlyBrowser")))
}

func TestBlockKnownAIBots(t *testing.T) {

	dome := New(RemoteAddr, BlockKnownAIBots())
	t.Cleanup(dome.Close)

	require.NotNil(t, dome.blockedUserAgents)
	require.True(t, dome.blockedUserAgents.Contains([]byte("ClaudeBot")))
	require.True(t, dome.blockedUserAgents.Contains([]byte("GPTBot")))
}

func TestBlockKnownBadBots(t *testing.T) {

	dome := New(RemoteAddr, BlockKnownBadBots())
	t.Cleanup(dome.Close)

	require.NotNil(t, dome.blockedUserAgents)

	// AllKnownBadBots includes the AI bots...
	require.True(t, dome.blockedUserAgents.Contains([]byte("ClaudeBot")))

	// ...as well as the wider bad-bot list.
	require.True(t, dome.blockedUserAgents.Contains([]byte("404checker")))
}

/******************************************
 * Block Path Options
 ******************************************/

func TestBlockPaths(t *testing.T) {

	dome := New(RemoteAddr, BlockPaths("/secret", "/admin"))
	t.Cleanup(dome.Close)

	require.NotNil(t, dome.blockedPaths)
	require.True(t, dome.blockedPaths.Contains([]byte("/secret")))
	require.True(t, dome.blockedPaths.Contains([]byte("/admin")))
	require.False(t, dome.blockedPaths.Contains([]byte("/welcome")))
}

func TestSoftBlockPaths(t *testing.T) {

	dome := New(RemoteAddr, SoftBlockPaths("/maybe", "/suspicious"))
	t.Cleanup(dome.Close)

	require.NotNil(t, dome.softBlockedPaths)
	require.True(t, dome.softBlockedPaths.Contains([]byte("/maybe")))
	require.True(t, dome.softBlockedPaths.Contains([]byte("/suspicious")))
	require.False(t, dome.softBlockedPaths.Contains([]byte("/welcome")))
}

/******************************************
 * Status Code Options
 ******************************************/

func TestLogStatusCodes(t *testing.T) {

	dome := New(RemoteAddr, LogStatusCodes(404, 410))
	t.Cleanup(dome.Close)

	require.Equal(t, []int{404, 410}, dome.logStatusCodes)
}

func TestBlockStatusCodes(t *testing.T) {

	dome := New(RemoteAddr, BlockStatusCodes(403, 429))
	t.Cleanup(dome.Close)

	require.Equal(t, []int{403, 429}, dome.blockStatusCodes)
}

/******************************************
 * Log Database Option
 ******************************************/

func TestLogDatabase(t *testing.T) {

	collection := &fakeCollection{}
	dome := New(RemoteAddr, LogDatabase(collection))
	t.Cleanup(dome.Close)

	require.NotNil(t, dome.logDatabase)
	require.Same(t, collection, dome.logDatabase)
}

/******************************************
 * Block Cache Option
 ******************************************/

func TestBlockCache_ChangesCapacity(t *testing.T) {

	dome := New(RemoteAddr) // default capacity is 1024
	t.Cleanup(dome.Close)
	require.Equal(t, 1024, dome.blockedIPs.Capacity())

	dome.With(BlockCache(2048))
	require.Equal(t, 2048, dome.blockedIPs.Capacity())
}

func TestBlockCache_SameCapacityIsNoOp(t *testing.T) {

	dome := New(RemoteAddr) // default capacity is 1024
	t.Cleanup(dome.Close)

	// Requesting the same capacity should leave the cache untouched (no rebuild).
	dome.With(BlockCache(1024))
	require.Equal(t, 1024, dome.blockedIPs.Capacity())
}

/******************************************
 * With
 ******************************************/

func TestWith_AppliesMultipleOptions(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	dome.With(
		BlockUserAgents("Zzz"),
		BlockPaths("/zzz"),
		LogStatusCodes(418),
	)

	require.True(t, dome.blockedUserAgents.Contains([]byte("Zzz")))
	require.True(t, dome.blockedPaths.Contains([]byte("/zzz")))
	require.Equal(t, []int{418}, dome.logStatusCodes)
}

func TestWith_NoOptions(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// Applying zero options should not panic or alter the defaults.
	dome.With()
	require.Equal(t, 1024, dome.blockedIPs.Capacity())
}

/******************************************
 * Test Helpers
 ******************************************/

// newTestRequest builds an *http.Request with the provided method, path,
// user-agent, and remote address for use in option/dome tests.
func newTestRequest(method string, path string, userAgent string, remoteAddr string) *http.Request {

	requestURL, _ := url.Parse("http://example.com" + path)

	return &http.Request{
		Method:     method,
		Host:       "example.com",
		URL:        requestURL,
		RemoteAddr: remoteAddr,
		Header: http.Header{
			"User-Agent": []string{userAgent},
		},
	}
}
