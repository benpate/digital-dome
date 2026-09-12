package dome

import (
	"net/http"
	"testing"

	"github.com/benpate/derp"
	"github.com/stretchr/testify/require"
)

func TestBlockedPaths_Signatures(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// Each of these is a framework this application does not run, so a false positive is impossible.
	paths := []string{
		"/actuator/env",
		"/api/rsc",
		"/_ignition/execute-solution",
		"/_next/static/chunks/main.js",
		"/_rsc",
		"/storage/logs/laravel.log",
		"/__vite_rsc_findSourceMapURL",
	}

	for _, path := range paths {
		err := dome.VerifyRequest(newTestRequest("GET", path, "GoodBrowser", "1.2.3.4:5678"))
		require.NotNil(t, err, path)
		require.Equal(t, http.StatusForbidden, derp.ErrorCode(err), path)
	}
}

func TestBlockedPaths_EncodedTraversal(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// Go decodes "%2f" into "/" when it populates URL.Path, so the literal "/../" signature
	// catches an encoded traversal probe. Asserted rather than assumed.
	request := newTestRequest("GET", "/@fs/..%2f..%2f..%2fproc/self/environ", "GoodBrowser", "1.2.3.4:5678")
	require.Equal(t, "/@fs/../../../proc/self/environ", request.URL.Path)

	err := dome.VerifyRequest(request)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, derp.ErrorCode(err))
}

func TestSuspiciousPaths_ArchivesAreSoftBlocked(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// An application may serve a real archive, so these must never be blocked outright.
	paths := []string{
		"/backup.7z",
		"/config.bak",
		"/web.rar",
		"/dump.sql",
		"/wwwroot.tar.gz",
		"/old.tgz",
		"/bandwagon.fm.zip",
	}

	for _, path := range paths {
		require.Nil(t, dome.VerifyRequest(newTestRequest("GET", path, "GoodBrowser", "1.2.3.4:5678")), path)
		require.True(t, dome.softBlockedPaths.Contains([]byte(path)), path)
	}
}

func TestSuspiciousPaths_ViteAndMCPAreSoftBlocked(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// "/@fs/" cannot be hard-blocked where the application's own namespace starts with "@",
	// and "/mcp" is short enough that the application may want the route itself.
	for _, path := range []string{"/@fs/app/rootkey.csv", "/mcp"} {
		require.Nil(t, dome.VerifyRequest(newTestRequest("GET", path, "GoodBrowser", "1.2.3.4:5678")), path)
		require.True(t, dome.softBlockedPaths.Contains([]byte(path)), path)
	}
}

func TestBlockedPaths_WebShellProbes(t *testing.T) {

	dome := New(RemoteAddr)
	t.Cleanup(dome.Close)

	// The ALFA TEaM Shell hunts for a backdoor left by an earlier compromise, walking its own
	// directories under whatever path prefixes the site happens to expose.
	paths := []string{
		"/albums/ALFA_DATA/alfacgiapi/perl.alfa",
		"/home/alfacgiapi/py.alfa",
		"/home/ERENUSE/bash.Eren",
		"/albums/ERENUSE/Erencgiapi/py.Eren",
		"/ALFA_DATA",
	}

	for _, path := range paths {
		err := dome.VerifyRequest(newTestRequest("GET", path, "GoodBrowser", "1.2.3.4:5678"))
		require.NotNil(t, err, path)
		require.Equal(t, http.StatusForbidden, derp.ErrorCode(err), path)
	}
}
