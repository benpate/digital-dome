package dome

// BlockedPaths lists out common paths that are scanned by bots
// for vunerabilities.
var BlockedPaths = []string{
	"/application.properties", // Java properties file
	"/.aws/",                  // AWS directory
	"/.aws.yml",               // AWS configuration file
	"/.env",                   // System Environment file
	"/.cgi-bin",               // CGI directory
	"/.git/",                  // Git repository
	"/.vscode/",               // Visual Studio Code directory

	".php", // WordPress XML-RPC interface

	"/aspera/faspex",      // CVE-2024-45096 (Aspera Faspex)
	"/config.json",        // JSON configuration file
	"/elfinder/connector", // CVE-2021-32682 (elFinder file manager)

	"/media/system/js/core.js", // Joomla core.js
	"/net/controller.ashx",     // .NET controller
	"/phpinfo",                 // PHP
	"/sftp-config.json",        // CVE-2024-20262 (Cisco IOS Secure Copy)
	"/utility/ueditor",         // CVE-2023-2245 (Hansun CMS)
	"/wp-admin",                // WordPress admin pages
	"/wp-content",              // WordPress content directory
	"/wp-includes",             // WordPress includes directory
	"/wp-json",                 // WordPress JSON directory
}

// SuspiciousPaths are not preemptively blocked, but will
// count towards a client's score if they return a 404 error
var SuspiciousPaths = []string{
	"/aspera/",
	"/about/more",
	"/actopms",
	"/admin.zip",
	"/administrator.zip",
	"/backup",
	"/backups",
	"/bc",
	"/bk",
	"/bkp",
	"/blog",
	"/config",
	"/credentials",
	"/db",
	"/dbadmin",
	"/db-admin",
	"/db-admin.php",
	"/dump.sql",
	"/feed",
	"/info",
	"/infos",
	"/includ",
	"/include",
	"/main",
	"/new",
	"/old",
	"/phpunit",
	"/Public/",
	"/renderers",
	"/static/",
	"/temp",
	"/test",
	"/wordpress",
	"/workflow",
	"/wp",
}
