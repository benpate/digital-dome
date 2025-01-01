package dome4echo

import (
	"net/http"

	"github.com/benpate/derp"
	"github.com/benpate/digital-dome/dome"
	"github.com/labstack/echo/v4"
)

// New returns an echo MiddlewareFunc that scans every request using Silicon Dome.
func New(d *dome.Dome) echo.MiddlewareFunc {

	return func(next echo.HandlerFunc) echo.HandlerFunc {

		return func(ctx echo.Context) error {

			// If this request is blocked, then halt here.
			if err := d.VerifyRequest(ctx.Request()); err != nil {
				_ = d.HandleError(ctx.Request(), err)
				ctx.Response().Header().Set("X-Dome-Blocked", derp.Message(err))
				return ctx.String(http.StatusForbidden, "Forbidden")
			}

			// Try to execute the request
			if err := next(ctx); err != nil {
				return d.HandleError(ctx.Request(), err)
			}

			// Done.
			return nil
		}
	}
}
