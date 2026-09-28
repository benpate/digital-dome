package dome

// BlockedQueryParams lists query parameter NAMES that identify a vulnerability
// probe, no matter which path the request is aimed at.
var BlockedQueryParams = []string{
	"page_id",          // WordPress page lookup under plain permalinks
	"raw??",            // Vite dev-server file read, CVE-2025-30208: /@fs/etc/passwd?raw??
	"rest_route",       // WordPress serves its whole REST API here when a site uses plain permalinks
	"wicket:interface", // Apache Wicket form-listener probe
}
