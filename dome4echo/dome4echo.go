// Package dome4echo adapts a digital-dome Dome into echo router middleware.
package dome4echo

import (
	"errors"
	"net/http"

	"github.com/benpate/derp"
	"github.com/benpate/digital-dome/dome"
	"github.com/labstack/echo/v4"
)

// New returns an echo MiddlewareFunc that scans every request using Digital Dome.
func New(d *dome.Dome) echo.MiddlewareFunc {

	return func(next echo.HandlerFunc) echo.HandlerFunc {

		return func(ctx echo.Context) error {

			// RULE: Blocked requests halt here, and never reach the next handler
			if err := d.VerifyRequest(ctx.Request()); err != nil {
				_ = d.HandleError(ctx.Request(), err)
				ctx.Response().Header().Set("X-Dome-Blocked", derp.Message(err))
				return ctx.String(http.StatusForbidden, "Forbidden")
			}

			// Try to execute the request
			if err := next(ctx); err != nil {
				return d.HandleError(ctx.Request(), withStatusCode(err))
			}

			// Done.
			return nil
		}
	}
}

// withStatusCode returns an error that reports the status code Echo would send.
func withStatusCode(err error) error {

	const location = "dome4echo.withStatusCode"

	// Echo answers its OWN routing failures (404 Not Found, 405 Method Not Allowed) with
	// *echo.HTTPError, a type derp does not recognize -- so derp.ErrorCode reads every one of
	// them as a generic 500. Uncorrected, Dome classifies a router error by the wrong status.

	var httpError *echo.HTTPError

	if errors.As(err, &httpError) {
		return derp.Wrap(err, location, http.StatusText(httpError.Code), derp.WithCode(httpError.Code))
	}

	return err
}
