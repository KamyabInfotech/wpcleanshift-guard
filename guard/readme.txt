=== CleanShift Guard ===
Contributors: kamyabinfotech
Tags: security, malware scanner, database scanner, wordpress security, malware removal
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

The first WordPress security plugin that scans your database for rogue admins, wp_options injections, and SEO spam — not just files.

== Description ==

CleanShift Security is the first WordPress security plugin that goes beyond file scanning to detect threats hiding in your database.

Traditional security plugins like Wordfence and Sucuri scan your files — but modern WordPress malware increasingly lives in the database. Rogue admin accounts, malicious wp_options payloads, and SEO spam injected directly into wp_posts survive file-level cleanups entirely.

CleanShift Guard detects these threats and shows you exactly how to fix them.

**What CleanShift detects that others don't:**

* 🔍 Rogue administrator accounts (created by exploits like CVE-2024-28000)
* 🔍 Malicious wp_options entries (redirect injections, eval() payloads)
* 🔍 SEO spam injected directly into wp_posts content
* 🔍 Modified WordPress core files (hash comparison against WordPress.org)
* 🔍 Suspicious mu-plugins and drop-ins

**Real-time protection:**

* 🛡️ Blocks PHP file uploads to /wp-content/uploads/
* 🛡️ Locks down XML-RPC abuse (pingback DDoS, brute-force)
* 🛡️ Protects REST API endpoints from unauthorized access
* 🛡️ Blocks login brute-force attempts with intelligent rate limiting
* 🛡️ Monitors wp-cron for suspicious scheduled events
* 🛡️ Prevents theme/plugin editor abuse

**Manual fix instructions included — no paywall on information:**

Every threat CleanShift finds comes with step-by-step instructions to fix it manually. We believe you should always know what's wrong and how to fix it yourself.

Need to fix 50+ threats across multiple sites automatically? [Upgrade to CleanShift Pro](https://pay.kamyab.co.in) for one-click auto-remediation.

**Server-wide scanning (optional):**

Managing a cPanel/WHM or Plesk server with multiple WordPress sites? Install the free [CleanShift Agent](https://cleanshift.osg.co.in/docs) for server-wide deep scanning, cross-site correlation, and fleet management.

**Privacy-first:**

* All Guard logs are stored locally in your WordPress database
* Nothing is transmitted to external servers unless you explicitly connect to the CleanShift API
* [Read our privacy policy](https://cleanshift.osg.co.in/privacy)

== Installation ==

**Automatic installation (recommended):**

1. Go to Plugins → Add New in your WordPress admin
2. Search for "CleanShift Security"
3. Click "Install Now" and then "Activate"
4. Go to CleanShift → Dashboard in your admin menu

**Manual installation:**

1. Download the plugin zip from WordPress.org
2. Go to Plugins → Add New → Upload Plugin
3. Upload the zip file and activate

**Server-wide installation (for hosting providers):**

To deploy Guard as a mu-plugin across all WordPress sites on a server:

`bash -c "$(curl -fsSL https://get.cleanshift.osg.co.in/guard)"`

== External Services ==

CleanShift Guard can optionally send security event data to the CleanShift API for centralized monitoring and threat intelligence. This functionality is **entirely optional** and **disabled by default** — no data is transmitted unless you explicitly configure an API connection.

When configured, the following data may be sent to the CleanShift API:

* Guard security events (blocked attacks, login attempts, upload blocks)
* Site URL and server information
* Timestamps of security events

**Service URL:** https://api-cleanshift.osg.co.in
**Privacy Policy:** https://cleanshift.osg.co.in/privacy
**Terms of Service:** https://cleanshift.osg.co.in/terms

No data is collected, transmitted, or processed when the API connection is not configured. All guard logs are always stored locally in your WordPress database regardless of API configuration.

== Frequently Asked Questions ==

= How is this different from Wordfence or Sucuri? =

Wordfence and Sucuri primarily scan files. CleanShift scans both files AND your WordPress database. Modern malware like rogue admin injections, wp_options payloads, and SEO spam in wp_posts are invisible to file-only scanners.

= Does this plugin require a paid subscription? =

No. CleanShift Guard is 100% free and fully functional. It detects threats and shows you how to fix them manually. The paid tiers (Pro, Server, Fleet) add auto-remediation, real-time intelligence, and server-wide scanning.

= Does this plugin send my data to external servers? =

No. All Guard logs and scan results are stored locally in your WordPress database. Nothing is transmitted externally unless you explicitly connect to the CleanShift API.

= What PHP version do I need? =

PHP 7.4 or higher. PHP 8.0+ recommended.

= Does this work with other security plugins? =

Yes. CleanShift Guard is designed to complement existing security plugins, not replace them. It detects the database-level threats that file-only scanners miss.

= Does this slow down my site? =

No. Guard's real-time blocking operates at the WordPress bootstrap phase and adds less than 1ms to page load time. Database scanning runs on demand, not on every page load.

= I found a rogue admin. Is my site hacked? =

Likely yes. A rogue administrator account is a strong indicator of compromise. Follow the manual fix instructions provided by CleanShift, then scan for additional threats. Consider upgrading to Pro for automated cleanup.

== Screenshots ==

1. Dashboard showing threat summary and severity breakdown
2. Database scan results with rogue admin detection
3. Manual fix instructions for each finding
4. Real-time Guard protection status
5. Audit log of blocked attacks

== Changelog ==

= 1.3.1 =
* Security: Guard IP detection hardened — replaced unsafe `get_client_ip()` with `CleanShift_Client_IP` trait that gates proxy header trust behind `CLEANSHIFT_TRUSTED_PROXY`
* Fixed: Guard admin UI now shows all 10 guards (was missing payload, request, vpatch)

= 1.3.0 =
* Added: Guard hardening pass — expanded community YARA rule library from 32 to 100 rules for broader malware family detection
* Added: Payload-inspection and virtual-patching guards wired into the PHP runtime protection layer
* Fixed: Resolved YARA rule duplication that could cause false-positive matches
* Fixed: Null-safety fixes across guard modules to prevent crashes on malformed request data

= 1.2.0 =
* Added: Guard API reporting improvements and N+1 query elimination for site listings

= 1.1.0 =
* Added: Dashboard 2FA enrollment UI and audit-log viewer
* Fixed: `.htaccess` whitelist regex corrected for LiteSpeed compatibility
* Fixed: 40+ audit fixes across dashboard and API (input validation, error handling, missing RBAC checks, UI regressions)

= 1.0.0 =
* Initial release
* Database scanning: rogue admins, wp_options payloads, SEO spam
* File scanning: core file integrity, suspicious uploads, fake mu-plugins
* Real-time Guard: upload protection, XML-RPC lockdown, REST API guard, login protection, cron monitoring
* WordPress admin dashboard with threat overview
* Manual remediation instructions for every finding
* Audit logging for all blocked requests

== Upgrade Notice ==

= 1.3.1 =
Security hardening for Guard IP detection and admin UI fix.

= 1.3.0 =
YARA rule expansion (32→100 rules), payload-inspection and virtual-patching guards added.

= 1.2.0 =
Guard reporting improvements and query performance fixes.

= 1.1.0 =
LiteSpeed compatibility fix, 2FA enrollment, 40+ security audit fixes.

= 1.0.0 =
Initial release. Install to scan your WordPress database for threats that file-only scanners miss.
