package dome4echo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/benpate/derp"
	"github.com/benpate/digital-dome/dome"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// newContext builds an echo.Context and its underlying ResponseRecorder for a
// request with the given path and User-Agent.
func newContext(path string, userAgent string) (echo.Context, *httptest.ResponseRecorder) {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("User-Agent", userAgent)
	request.RemoteAddr = "1.2.3.4:5678"

	recorder := httptest.NewRecorder()
	return echo.New().NewContext(request, recorder), recorder
}

// A blocked request returns 403, sets the X-Dome-Blocked header, and never calls
// the downstream handler.
func TestNew_BlocksRequest(t *testing.T) {

	d := dome.New(dome.RemoteAddr)
	t.Cleanup(d.Close)

	nextCalled := false
	handler := New(d)(func(echo.Context) error {
		nextCalled = true
		return nil
	})

	// An empty User-Agent is always blocked by VerifyRequest.
	ctx, recorder := newContext("/welcome", "")

	require.NoError(t, handler(ctx))
	require.False(t, nextCalled) // downstream handler must not run
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.NotEmpty(t, recorder.Header().Get("X-Dome-Blocked"))
}

// An allowed request passes through to the downstream handler.
func TestNew_AllowsRequest(t *testing.T) {

	d := dome.New(dome.RemoteAddr)
	t.Cleanup(d.Close)

	nextCalled := false
	handler := New(d)(func(ctx echo.Context) error {
		nextCalled = true
		return ctx.String(http.StatusOK, "ok")
	})

	ctx, recorder := newContext("/welcome", "GoodBrowser")

	require.NoError(t, handler(ctx))
	require.True(t, nextCalled)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Empty(t, recorder.Header().Get("X-Dome-Blocked"))
}

// An error returned by the downstream handler is fed back into the Dome and
// returned to Echo (the middleware observes, it does not swallow).
func TestNew_PassesDownstreamErrorToDome(t *testing.T) {

	d := dome.New(dome.RemoteAddr)
	t.Cleanup(d.Close)

	downstreamErr := derp.Forbidden("test", "forbidden") // 403 is a default block status code
	handler := New(d)(func(echo.Context) error {
		return downstreamErr
	})

	ctx, _ := newContext("/welcome", "GoodBrowser")

	// The middleware returns the handler's error unchanged.
	require.Equal(t, downstreamErr, handler(ctx))
}
