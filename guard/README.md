<div align="center">

# 🛡️ CleanShift Guard

**The first WordPress security plugin that scans your database — not just files.**

[![WordPress](https://img.shields.io/badge/WordPress-5.8%2B-blue.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)](https://php.net)
[![License: GPLv2](https://img.shields.io/badge/License-GPLv2-green.svg)](LICENSE)

[Install from WordPress.org](https://wordpress.org/plugins/cleanshift-security) · [Documentation](https://cleanshift.osg.co.in/docs) · [Report a Bug](https://github.com/KamyabInfotech/cleanshift-guard/issues)

</div>

## The Problem

Modern WordPress malware lives in the database. Rogue admin accounts, wp_options redirect injections, SEO spam in wp_posts — these survive file-level cleanup entirely. Every file scanner on the market misses them.

## What CleanShift Guard Does

### Detection (free, always)
- 🔍 Scans `wp_users` for rogue administrator accounts (no email, recent creation, exploit patterns)
- 🔍 Scans `wp_options` for malicious payloads (base64, eval, redirect injections)
- 🔍 Scans `wp_posts` for SEO spam injection (Japanese keyword spam, pharma redirects)
- 🔍 Checks WordPress core file integrity against official checksums
- 🔍 Detects suspicious mu-plugins and drop-ins

### Real-time Protection (free, always)
- 🛡️ Blocks PHP uploads to `/wp-content/uploads/`
- 🛡️ Locks XML-RPC (pingback DDoS, brute-force)
- 🛡️ Protects REST API from unauthorized access
- 🛡️ Rate-limits login attempts
- 🛡️ Monitors wp-cron for suspicious scheduled events
- 🛡️ Blocks theme/plugin editor abuse

### Manual Fix Instructions (free, always)
Every finding includes step-by-step instructions to fix it yourself. **No paywall on information.**

### Auto-Remediation (paid upgrade)
Connect to [CleanShift Pro](https://pay.kamyab.co.in) ($5/mo) for one-click automated cleanup.

## Quick Start

```bash
# From WordPress admin
Plugins → Add New → Search "CleanShift Security" → Install → Activate

# Or as a mu-plugin on a server (for hosting providers)
bash -c "$(curl -fsSL https://get.cleanshift.osg.co.in/guard)"
```

## Architecture

| Module | File | Purpose |
|---|---|---|
| Request Guard | `class-request-guard.php` | Core request filtering engine |
| Upload Guard | `class-upload-guard.php` | Blocks PHP uploads to /uploads/ |
| Login Guard | `class-login-guard.php` | Brute-force protection |
| API Guard | `class-api-guard.php` | REST API endpoint protection |
| User Guard | `class-user-guard.php` | Rogue admin detection |
| Option Guard | `class-option-guard.php` | Malicious wp_options detection |
| Cron Guard | `class-cron-guard.php` | Suspicious scheduled event monitoring |
| Editor Guard | `class-editor-guard.php` | Theme/plugin editor lockdown |
| Payload Guard | `class-payload-guard.php` | Malicious payload detection |
| VPatch Guard | `class-vpatch-guard.php` | Virtual patching for known CVEs |
| Audit Log | `class-audit-log.php` | Local audit trail |
| Admin UI | `class-admin-ui.php` | WordPress admin dashboard |
| API Reporter | `class-api-reporter.php` | Optional CleanShift API integration |
| Security Stack | `class-security-stack.php` | Detects other security tools |
| Override Manager | `class-override-manager.php` | Per-site configuration overrides |

## Privacy

- All logs stored locally in your WordPress database
- Nothing transmitted externally unless you connect to CleanShift API
- Read the full [Privacy Policy](https://cleanshift.osg.co.in/privacy)

## Server-Wide Scanning

Guard protects individual WordPress sites. For server-wide deep scanning across all sites on a cPanel/Plesk server, install the [CleanShift Agent](https://github.com/KamyabInfotech/cleanshift-agent) (also open source, Apache 2.0).

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting PRs.

## License

GPLv2 or later. See [LICENSE](LICENSE).

## Support

- 💬 WhatsApp: [+91 845 409 4444](https://wa.me/918454094444)
- 🌐 Website: [cleanshift.osg.co.in](https://cleanshift.osg.co.in)
- 🐛 Issues: [GitHub Issues](https://github.com/KamyabInfotech/cleanshift-guard/issues)

---

Built by [Kamyab Infotech](https://kamyab.co.in).
