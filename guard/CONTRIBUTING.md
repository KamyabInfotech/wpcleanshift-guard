# Contributing to CleanShift Guard

Thank you for your interest in contributing to CleanShift Guard! This document provides guidelines for contributing.

## How to Contribute

### Reporting Bugs
- Use [GitHub Issues](https://github.com/KamyabInfotech/cleanshift-guard/issues)
- Include: WordPress version, PHP version, error messages, steps to reproduce
- **Do not include sensitive data** (passwords, API keys, server IPs)

### Suggesting Detection Rules
If you've found a new malware pattern that CleanShift Guard should detect:
1. Open an issue with the tag `detection-rule`
2. Include: pattern description, sample hash (SHA-256), affected WordPress versions
3. **Do not submit actual malware samples** — hashes and descriptions only

### Submitting Code
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Test on a WordPress installation (5.8+ with PHP 7.4+)
5. Submit a pull request

### Code Style
- Follow WordPress PHP coding standards
- Use descriptive class and method names
- Add PHPDoc comments for public methods
- Guard modules should extend the existing class pattern (see `class-upload-guard.php` for reference)

## What We Accept
- Bug fixes
- New detection rules (rogue admin patterns, malicious wp_options patterns)
- Performance improvements
- Compatibility fixes for newer WordPress/PHP versions
- Documentation improvements
- Translations

## What We Don't Accept
- Features that require external API calls (Guard must work offline)
- Auto-remediation logic (this is part of the proprietary CleanShift Pro)
- Dependencies on external PHP libraries (Guard must be zero-dependency)

## Security Vulnerabilities
If you discover a security vulnerability in CleanShift Guard, please **do not** open a public issue. Instead, email security@cleanshift.osg.co.in with details. We will respond within 48 hours.

## License
By contributing, you agree that your contributions will be licensed under the GPLv2 license.
