package dome

// BlockedRequestHeaders lists request header NAMES that only a vulnerability
// probe sends to a Go application, whatever their values.
var BlockedRequestHeaders = []string{
	"Next-Action",             // Next.js Server Actions probe, POSTed to ordinary pages with junk ids and payloads
	"X-Middleware-Subrequest", // Next.js middleware bypass, CVE-2025-29927
	"X-Nextjs-Data",           // Next.js cache-poisoning probe, CVE-2024-46982
	"X-Forwared",              // Misspelled by an IP-spoofing kit that sends it beside X-Client-Ip: 127.0.0.1
}
