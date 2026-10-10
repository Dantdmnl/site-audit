"""Endpoint inventories and passive technology/body patterns."""
from __future__ import annotations

import re

COMMON_PATHS: list[tuple[str, str, str]] = [
    # Info / recon
    ("/robots.txt",               "INFO",     "robots.txt"),
    ("/sitemap.xml",              "INFO",     "sitemap"),
    ("/.well-known/security.txt", "INFO",     "security.txt"),
    ("/security.txt",             "INFO",     "security.txt (root)"),
    ("/crossdomain.xml",          "MEDIUM",   "Flash crossdomain policy"),
    ("/clientaccesspolicy.xml",   "MEDIUM",   "Silverlight access policy"),
    # Admin surfaces
    ("/admin/",                   "HIGH",     "admin panel"),
    ("/administrator/",           "HIGH",     "admin panel"),
    ("/login/",                   "MEDIUM",   "login page"),
    ("/dashboard/",               "MEDIUM",   "dashboard"),
    ("/register/",                "LOW",      "registration page"),
    ("/user/login",               "MEDIUM",   "user login"),
    # APIs & schemas
    ("/api/",                     "LOW",      "API root"),
    ("/api/v1/",                  "LOW",      "API v1"),
    ("/api/v2/",                  "LOW",      "API v2"),
    ("/api/v3/",                  "LOW",      "API v3"),
    ("/graphql",                  "MEDIUM",   "GraphQL endpoint"),
    ("/graphiql",                 "HIGH",     "GraphiQL IDE (interactive)"),
    ("/swagger.json",             "MEDIUM",   "Swagger/OpenAPI spec"),
    ("/swagger-ui.html",          "MEDIUM",   "Swagger UI"),
    ("/openapi.json",             "MEDIUM",   "OpenAPI spec"),
    ("/api-docs",                 "MEDIUM",   "API docs"),
    # Health / monitoring
    ("/health",                   "LOW",      "health endpoint"),
    ("/healthz",                  "LOW",      "health endpoint"),
    ("/ping",                     "LOW",      "ping endpoint"),
    ("/status",                   "LOW",      "status endpoint"),
    ("/metrics",                  "MEDIUM",   "Prometheus metrics"),
    ("/ready",                    "LOW",      "readiness probe"),
    # Sensitive files — CRITICAL if reachable
    ("/.env",                     "CRITICAL", ".env file (credentials)"),
    ("/.env.production",          "CRITICAL", ".env.production"),
    ("/.env.local",               "CRITICAL", ".env.local"),
    ("/.git/config",              "CRITICAL", "git config (repo leak)"),
    ("/.git/HEAD",                "CRITICAL", "git HEAD"),
    ("/.svn/entries",             "CRITICAL", "SVN entries"),
    ("/.htaccess",                "HIGH",     ".htaccess rules"),
    ("/web.config",               "HIGH",     "web.config"),
    ("/config.json",              "HIGH",     "config.json"),
    ("/config.yaml",              "HIGH",     "config.yaml"),
    ("/config.yml",               "HIGH",     "config.yml"),
    ("/database.yml",             "HIGH",     "database config"),
    ("/secrets.json",             "CRITICAL", "secrets file"),
    ("/credentials.json",         "CRITICAL", "credentials file"),
    ("/backup.sql",               "CRITICAL", "SQL backup"),
    ("/dump.sql",                 "CRITICAL", "SQL dump"),
    # Debug / dev leftovers
    ("/debug/",                   "HIGH",     "debug panel"),
    ("/debug",                    "HIGH",     "debug endpoint"),
    ("/trace",                    "MEDIUM",   "trace endpoint"),
    ("/phpinfo.php",              "HIGH",     "phpinfo()"),
    ("/info.php",                 "HIGH",     "phpinfo()"),
    ("/test.php",                 "MEDIUM",   "test PHP file"),
    ("/backup/",                  "HIGH",     "backup directory"),
    ("/old/",                     "MEDIUM",   "old/ directory"),
    ("/dev/",                     "HIGH",     "dev/ directory"),
    ("/staging/",                 "HIGH",     "staging directory"),
    ("/temp/",                    "MEDIUM",   "temp directory"),
    ("/tmp/",                     "MEDIUM",   "tmp directory"),
]


PLATFORM_PATHS: dict[str, list[tuple[str, str, str]]] = {
    "wordpress": [
        ("/wp-admin/",                  "HIGH",     "WP admin panel"),
        ("/wp-login.php",               "HIGH",     "WP login"),
        ("/xmlrpc.php",                 "HIGH",     "XML-RPC (brute/SSRF vector)"),
        ("/wp-json/",                   "LOW",      "WP REST API root"),
        ("/wp-json/wp/v2/users",        "HIGH",     "WP user enumeration endpoint"),
        ("/wp-content/debug.log",       "CRITICAL", "WP debug log"),
        ("/wp-config.php",              "CRITICAL", "WP config (credentials)"),
        ("/wp-config.php.bak",          "CRITICAL", "WP config backup"),
        ("/wp-config-sample.php",       "LOW",      "WP sample config"),
        ("/readme.html",                "LOW",      "WP version disclosure"),
        ("/license.txt",                "INFO",     "WP license"),
        ("/wp-sitemap.xml",             "INFO",     "WP sitemap"),
    ],
    "drupal": [
        ("/user/login",                 "MEDIUM",   "Drupal login"),
        ("/user/register",              "MEDIUM",   "Drupal registration"),
        ("/admin/config",               "HIGH",     "Drupal config"),
        ("/update.php",                 "CRITICAL", "Drupal update script"),
        ("/install.php",                "CRITICAL", "Drupal install script"),
        ("/CHANGELOG.txt",              "MEDIUM",   "Drupal version disclosure"),
        ("/core/CHANGELOG.txt",         "MEDIUM",   "Drupal core version"),
        ("/sites/default/settings.php", "CRITICAL", "Drupal settings (credentials)"),
        ("/sites/default/files/",       "MEDIUM",   "Drupal public files"),
    ],
    "joomla": [
        ("/administrator/",             "HIGH",     "Joomla admin"),
        ("/administrator/index.php",    "HIGH",     "Joomla admin login"),
        ("/README.txt",                 "LOW",      "Joomla version disclosure"),
        ("/htaccess.txt",               "LOW",      "Joomla .htaccess sample"),
        ("/web.config.txt",             "LOW",      "Joomla web.config sample"),
        ("/cache/",                     "MEDIUM",   "Joomla cache directory"),
        ("/components/",               "LOW",      "Joomla components"),
    ],
    "laravel": [
        ("/storage/logs/laravel.log",   "CRITICAL", "Laravel log file"),
        ("/telescope",                  "HIGH",     "Laravel Telescope"),
        ("/horizon",                    "HIGH",     "Laravel Horizon"),
        ("/api/user",                   "MEDIUM",   "Laravel API user endpoint"),
        ("/_ignition/health-check",     "LOW",      "Ignition health"),
        ("/_ignition/execute-solution", "CRITICAL", "Ignition RCE endpoint"),
    ],
    "django": [
        ("/admin/",                     "HIGH",     "Django admin"),
        ("/api/schema/",                "MEDIUM",   "Django schema"),
        ("/api/docs/",                  "MEDIUM",   "Django API docs"),
        ("/__debug__/",                 "HIGH",     "Django Debug Toolbar"),
    ],
    "aspnet": [
        ("/elmah.axd",                  "HIGH",     "ELMAH error log"),
        ("/trace.axd",                  "HIGH",     "ASP.NET trace"),
        ("/ScriptResource.axd",         "LOW",      "ASP.NET resources"),
    ],
    "symfony": [
        ("/app_dev.php",                "HIGH",     "Symfony dev frontend"),
        ("/app_dev.php/_profiler/",     "HIGH",     "Symfony profiler"),
        ("/_profiler/",                 "HIGH",     "Symfony profiler"),
        ("/_wdt/",                      "MEDIUM",   "Symfony web debug toolbar"),
    ],
    "rails": [
        ("/rails/info/properties",      "HIGH",     "Rails info (env disclosure)"),
        ("/rails/info/routes",          "MEDIUM",   "Rails route list"),
        ("/sidekiq",                    "HIGH",     "Sidekiq web UI"),
        ("/letter_opener",              "MEDIUM",   "Letter Opener (email preview)"),
    ],
    "spring": [
        ("/actuator",                   "HIGH",     "Spring Actuator root"),
        ("/actuator/env",               "CRITICAL", "Spring env (credentials leak)"),
        ("/actuator/mappings",          "MEDIUM",   "Spring route mappings"),
        ("/actuator/beans",             "MEDIUM",   "Spring beans"),
        ("/actuator/health",            "LOW",      "Spring health"),
        ("/h2-console",                 "CRITICAL", "H2 database console"),
    ],
    "nextjs": [
        ("/_next/static/",              "INFO",     "Next.js static assets"),
    ],
}


SECURITY_HEADERS: list[tuple[str, str, str]] = [
    ("Strict-Transport-Security", "HIGH",   "HSTS not set — HTTPS not enforced"),
    ("Content-Security-Policy",   "HIGH",   "CSP not set — XSS/injection exposure"),
    ("X-Content-Type-Options",    "MEDIUM", "MIME sniffing not disabled"),
    ("X-Frame-Options",           "MEDIUM", "Clickjacking protection missing"),
    ("Referrer-Policy",           "LOW",    "Referrer-Policy not set"),
    ("Permissions-Policy",        "LOW",    "Permissions-Policy not set"),
    ("Cross-Origin-Opener-Policy","LOW",    "COOP not set"),
]


TECH_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "Via",
    "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Drupal-Cache", "X-WordPress-Cache",
]


WAPPALYZER_RULES: dict[str, list[tuple[str, str]]] = {
    "wordpress":  [(r"wp-content|wp-includes|wp-json", "html"),
                   (r"x-pingback", "headers"),
                   (r"wordpress", "cookies")],
    "drupal":     [(r"drupal|sites/default", "html"),
                   (r"x-generator.*drupal", "headers"),
                   (r"drupal", "cookies")],
    "joomla":     [(r"/media/system/js/|joomla", "html"),
                   (r"x-generator.*joomla", "headers")],
    "laravel":    [(r'name="csrf-token"|laravel', "html"),
                   (r"laravel_session|xsrf-token", "cookies")],
    "django":     [(r"csrfmiddlewaretoken|__admin_media", "html"),
                   (r"csrftoken", "cookies")],
    "aspnet":     [(r"__viewstate|webresource\.axd", "html"),
                   (r"x-aspnet-version|x-aspnetmvc-version", "headers"),
                   (r"asp\.net_sessionid", "cookies")],
    "symfony":    [(r"symfony", "html"), (r"sf_", "cookies")],
    "rails":      [(r"rails|data-turbo", "html"), (r"_rails|_session_id", "cookies")],
    "nextjs":     [(r"__next_data__|/_next/", "html")],
    "nuxtjs":     [(r"__nuxt__|/_nuxt/", "html")],
    "spring":     [(r"x-application-context", "headers"), (r"jsessionid", "cookies")],
    "express":    [(r"x-powered-by.*express", "headers")],
    "nginx":      [(r"nginx", "headers")],
    "apache":     [(r"apache", "headers")],
    "iis":        [(r"microsoft-iis", "headers")],
    "cloudflare": [(r"cf-ray|cloudflare", "headers"),
                   (r"__cfduid|cf_clearance", "cookies")],
    "varnish":    [(r"x-varnish|varnish", "headers")],
    "jquery":     [(r"jquery[.\-/][\d.]+", "html")],
    "react":      [(r"__reactfiber|data-reactroot|react(?:dom)?[.\-/][\d.]+", "html")],
    "vue":        [(r"vue[.\-/][\d.]+|data-v-", "html")],
    "bootstrap":  [(r"bootstrap[.\-/][\d.]+", "html")],
}


BODY_PATTERNS: list[tuple[str, str, str]] = [
    (r"stack trace|traceback \(most recent call\)|exception in thread",
     "HIGH",     "Stack trace / exception in response body"),
    (r"sql syntax|mysql_fetch|pg_query|sqlite3\.operationalerror|ora-\d{5}",
     "CRITICAL", "SQL error in response body (possible SQLi surface)"),
    (r'password\s*=\s*[\'"]?\w+|db_password|api_key\s*=\s*[\'"]?\w+',
     "CRITICAL", "Credential-like string in response body"),
    (r"PHP (Warning|Parse error|Fatal error|Notice)",
     "MEDIUM",   "PHP error visible in response body"),
    (r"<b>Warning</b>|<b>Notice</b>|<b>Fatal error</b>",
     "MEDIUM",   "PHP error (HTML formatted) in response body"),
    (r"Directory listing for|Index of /",
     "HIGH",     "Directory listing enabled"),
    (r'"access_token":|"secret":|"private_key":',
     "CRITICAL", "Sensitive key in response body"),
]


BODY_PATTERNS_COMPILED: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(pattern, re.I), severity, title)
    for pattern, severity, title in BODY_PATTERNS
]
