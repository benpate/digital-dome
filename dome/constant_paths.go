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
	"/.msmtprc",               // ???
	",create_function/",       // https://nvd.nist.gov/vuln/detail/CVE-2014-8877

	".asp",      // ASP files
	".aspx",     // ASPX files
	".php",      // PHP files
	"/php-cgi/", // PHP directories
	"/phpinfo",  // Misc PHP

	"/s3cmd",              // s3cmd configuration file
	"/aspera/faspex",      // CVE-2024-45096 (Aspera Faspex)
	"/config.json",        // JSON configuration file
	"/elfinder/connector", // CVE-2021-32682 (elFinder file manager)

	"/media/system/js/core.js", // Joomla core.js
	"/net/controller.ashx",     // .NET controller
	"/sftp-config.json",        // CVE-2024-20262 (Cisco IOS Secure Copy)
	"/utility/ueditor",         // CVE-2023-2245 (Hansun CMS)
	"/wp-admin",                // WordPress admin pages
	"/wp-content",              // WordPress content directory
	"/wp-includes",             // WordPress includes directory
	"/wp-json",                 // WordPress JSON directory
	"/zb_users/",               // https://www.cvedetails.com/cve/CVE-2018-9169/
}

// SuspiciousPaths are not preemptively blocked, but will
// count towards a client's score if they return a 404 error
var SuspiciousPaths = []string{
	"/about/more",
	"/actopms",
	"/admin.zip",
	"/administrator.zip",
	"/allowurl.txt",
	"/app",
	"/api",
	"/aspera/",
	"/aspx/",
	"/backup",
	"/backups",
	"/bc",
	"/bk",
	"/bkp",
	"/blog",
	"/ckeditor",
	"/config",
	"/credentials",
	"/db",
	"/dbadmin",
	"/db-admin",
	"/db-admin.php",
	"/dump.sql",
	"/env",
	"/FCKeditor/",
	"/feed",
	"/info",
	"/infos",
	"/includ",
	"/include",
	"/main",
	"/new",
	"/old",
	"/pbhome",
	"/phobome",
	"/phpunit",
	"/Public/",
	"/renderers",
	"/static/",
	"/temp",
	"/test",
	"/Ueditor",
	"/ueditor",
	"/wap",
	"/wordpress",
	"/workflow",
	"/wp",
}
