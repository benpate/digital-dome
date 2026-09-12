package dome4echo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/benpate/data"
	"github.com/benpate/data/option"
	"github.com/benpate/derp"
	"github.com/benpate/digital-dome/dome"
	"github.com/benpate/exp"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// fakeCollection is a minimal in-memory data.Collection that records every object
// passed to Save, so a test can assert on logging without a database.
type fakeCollection struct {
	saved []data.Object
}

func (c *fakeCollection) Context() context.Context { return context.Background() }

func (c *fakeCollection) Count(exp.Expression, ...option.Option) (int64, error) {
	return int64(len(c.saved)), nil
}

func (c *fakeCollection) Save(object data.Object, _ string) error {
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

// Echo's own routing failures carry their status code in *echo.HTTPError, which derp
// reads as a generic 500. The middleware translates them before the Dome classifies them.
func TestNew_TranslatesEchoRoutingErrors(t *testing.T) {

	d := dome.New(dome.RemoteAddr)
	t.Cleanup(d.Close)

	testCases := []struct {
		name       string
		err        error
		statusCode int
	}{
		{"method not allowed", echo.ErrMethodNotAllowed, http.StatusMethodNotAllowed},
		{"not found", echo.ErrNotFound, http.StatusNotFound},
		{"payload too large", echo.ErrStatusRequestEntityTooLarge, http.StatusRequestEntityTooLarge},
	}

	for _, testCase := range testCases {

		// Confirm the premise: derp cannot read this type on its own.
		require.Equal(t, http.StatusInternalServerError, derp.ErrorCode(testCase.err), testCase.name)

		handler := New(d)(func(echo.Context) error {
			return testCase.err
		})

		ctx, _ := newContext("/welcome", "GoodBrowser")
		err := handler(ctx)

		require.Equal(t, testCase.statusCode, derp.ErrorCode(err), testCase.name)

		// The original error stays in the chain, so a downstream handler can still find it.
		var httpError *echo.HTTPError
		require.True(t, errors.As(err, &httpError), testCase.name)
		require.Equal(t, testCase.statusCode, httpError.Code, testCase.name)
	}
}

// A routing error is logged under the status code Echo would actually send.
func TestNew_LogsEchoRoutingErrorByItsOwnStatusCode(t *testing.T) {

	collection := &fakeCollection{}
	d := dome.New(dome.RemoteAddr, dome.LogDatabase(collection), dome.LogStatusCodes(http.StatusMethodNotAllowed))
	t.Cleanup(d.Close)

	handler := New(d)(func(echo.Context) error {
		return echo.ErrMethodNotAllowed
	})

	ctx, _ := newContext("/welcome", "GoodBrowser")
	_ = handler(ctx)

	require.Len(t, collection.saved, 1)
}
