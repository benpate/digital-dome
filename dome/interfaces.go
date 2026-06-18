package dome

import "net/http"

// ClientIPResolver returns the "real" client IP address for an HTTP request.
// It is modeled on github.com/realclientip/realclientip-go, which is intended
// to be used in when configuring Digital Dome.  If your calling app does not
// use the realclientip package, you can inject the RemoteAddr function from
// this package instead.
type ClientIPResolver func(*http.Request) string
