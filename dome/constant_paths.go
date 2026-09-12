package dome

// BlockedPaths lists out common paths that are scanned by bots
// for vulnerabilities.
var BlockedPaths = []string{
	"/application.properties", // Java properties file
	"/.aws/",                  // AWS directory
	"/.aws.yml",               // AWS configuration file
	"/.env",                   // System Environment file
	"/.cgi-bin",               // CGI directory
	"/.git/",                  // Git repository
	"/.vscode/",               // Visual Studio Code directory
	"/.msmtprc",               // ???
	"/.svn/",                  // Subversion repository
	"/kube",                   // Kubernetes directory
	",create_function/",       // https://nvd.nist.gov/vuln/detail/CVE-2014-8877
	"/../",                    // Path traversal. Go decodes "%2f" into "/", so an encoded probe arrives here already spelled this way

	".asp",      // ASP files
	".aspx",     // ASPX files
	".php",      // PHP files
	"/php-cgi/", // PHP directories
	"/phpinfo",  // Misc PHP

	"/graphql",     // GraphQL directory
	"/api/graphql", // GraphQL directory
	"/api/gql",     // GraphQL directory

	"/s3cmd",                   // s3cmd configuration file
	"/actuator/",               // Spring Boot Actuator; /actuator/env leaks credentials
	".alfa",                    // ALFA TEaM Shell payloads: bash.alfa, py.alfa, perl.alfa
	"/ALFA_DATA",               // ALFA TEaM Shell data directory
	"cgiapi/",                  // ALFA TEaM Shell CGI directory: alfacgiapi, Erencgiapi
	"/ERENUSE",                 // "Eren" fork of the ALFA TEaM Shell
	"/api/rsc",                 // React Server Components probe
	"/aspera/faspex",           // CVE-2024-45096 (Aspera Faspex)
	"/config.json",             // JSON configuration file
	"/elfinder/connector",      // CVE-2021-32682 (elFinder file manager)
	"/_ignition/",              // Laravel Ignition, CVE-2021-3129 (RCE)
	"/media/system/js/core.js", // Joomla core.js
	"/net/controller.ashx",     // .NET controller
	"/_next/",                  // Next.js internals
	"/_rsc",                    // React Server Components probe
	"/sftp-config.json",        // CVE-2024-20262 (Cisco IOS Secure Copy)
	"/storage/logs/",           // Laravel log disclosure
	"/utility/ueditor",         // CVE-2023-2245 (Hansun CMS)
	"vita/env",                 // seen in scan logs
	"vite/env",                 // seen in scan logs
	"/__vite",                  // Vite internals, incl. __vite_rsc_findSourceMapURL
	"vite.config.js",           // Vite configuration file
	"/webpack.config.js",       // Webpack configuration file
	"/wp-admin",                // WordPress admin pages
	"/wp-content",              // WordPress content directory
	"/wp-includes",             // WordPress includes directory
	"/wp-json",                 // WordPress JSON directory
	"/zb_users/",               // https://www.cvedetails.com/cve/CVE-2018-9169/
}

// SuspiciousPaths are not preemptively blocked, but will
// count towards a client's score if they return a 404 error
var SuspiciousPaths = []string{

	// Site-archive enumeration. These are SOFT-blocked because an application may
	// legitimately serve an archive or a dump; a real download answers 200 and never counts.
	".7z",
	".bak",
	".rar",
	".sql",
	".tar.gz",
	".tgz",
	".zip",

	"/about/more",
	"/actopms",
	"/admin.zip",
	"/administrator.zip",
	"/allowurl.txt",
	"/app",
	"/aspera/",
	"/aspx/",
	"/@fs/", // Vite filesystem access. Soft, because an application's own namespace may start with "@"
	"/aws_credentials",
	"/awsconfig.json",
	"/backup",
	"/backups",
	"/bc",
	"/bk",
	"/bkp",
	"/blog",
	"/ckeditor",
	"/config",
	".config",
	"/credentials",
	"/database.sql",
	"/db",
	"/dbadmin",
	"/db-admin",
	"/db-admin.php",
	"/.DS_Store",
	"/dump.sql",
	"/env",
	"/FCKeditor/",
	"/.gits",
	"/info",
	"/infos",
	"/includ",
	"/include",
	"/lkk_ch.js",
	"/main",
	"/mcp", // MCP endpoint probe. Soft, because it is short and an application may want the route
	"/new",
	"/old",
	"/pbhome",
	"/phobome",
	"/phpunit",
	"/Public/",
	"/renderers",
	"/sendgrid.env",
	"/static/",
	"/temp",
	"/test",
	"/twint_ch.js",
	"/Ueditor",
	"/ueditor",
	"/wap",
	"/win.ini",
	"/wordpress",
	"/workflow",
	"/wp",
	"/ws-config.json",
}
