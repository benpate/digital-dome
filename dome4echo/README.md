# dome4echo

Adapter that wraps a [`dome.Dome`](../dome) as [Echo](https://echo.labstack.com) router middleware. See the [root README](../README.md) for what Digital Dome does and how to configure a `Dome`.

```go
d := dome.New(dome.RemoteAddr, dome.BlockKnownBadBots())
e := echo.New()
e.Use(dome4echo.New(d))
```

## What matters here

- **One `Dome`, shared across every request.** Build and configure the `Dome` once, then hand it to `New`. The middleware closes over that single instance; do not call `dome.With(...)` after the server starts (it mutates without synchronization — see the `dome` package).

- **The middleware short-circuits blocked requests.** When `VerifyRequest` rejects a request, it returns `403 Forbidden` immediately and never calls `next` — the downstream handler doesn't run. The reason is surfaced in the `X-Dome-Blocked` response header (from `derp.Message`), which is convenient for debugging but exposes the block reason to clients; strip it at the edge if that matters.

- **Errors from `next` are fed back into the Dome.** A non-nil error returned by the downstream handler is passed to `HandleError`, which is how 4xx/5xx responses accrue against an IP's block score. The middleware returns that same error so Echo's own error handler still runs — Dome observes, it does not swallow.

- **Pair it with the right client-IP resolver.** The `Dome` is only as accurate as its `ClientIPResolver`. Behind a proxy, inject a proxy-aware resolver when constructing the `Dome`; otherwise scores and blocks attach to the proxy's address, not the real client. `dome4echo` itself does no IP resolution.
