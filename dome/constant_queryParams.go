package dome

// BlockedQueryParams lists query parameter NAMES that identify a vulnerability
// probe, no matter which path the request is aimed at.
var BlockedQueryParams = []string{
	"rest_route", // WordPress serves its whole REST API here when a site uses plain permalinks
}
