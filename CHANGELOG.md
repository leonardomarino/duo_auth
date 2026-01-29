# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.5] - 2025-01-29

### Security

- **CRITICAL**: Fixed authentication bypass vulnerability where users could skip Duo 2FA by pressing the browser back button after being redirected to Duo authentication. The fix adds a `startup` hook that detects incomplete authentication states and forces logout. All users should upgrade immediately.

### Added

- `startup()` hook to verify Duo authentication completion on every request
- `is_duo_auth_pending()` helper to detect incomplete auth states
- `is_duo_required_for_session()` helper to check bypass rules during startup
- New config options `duo_msg_incomplete` and `duo_msg_required` for custom error messages
- Comprehensive security test suite for the bypass vulnerability

### Fixed

- Back-button bypass allowing access without completing Duo authentication

## [2.0.0] - 2025-11-18

### Added

- Duo Universal Prompt support (OIDC/OAuth 2.0 flow)
- Flexible bypass system (global user, global IP, conditional user+IP)
- IPv4/IPv6 CIDR support for IP whitelisting
- Proxy header detection for client IP
- Failmode options (`secure` or `open`)
- Comprehensive logging with configurable levels
- PHP 8.2+ compatibility

### Changed

- Migrated from deprecated Duo Web SDK v2 to Universal Prompt
- Complete rewrite of authentication flow

### Removed

- Legacy iframe-based Duo prompt
- Duo Web SDK v2 dependencies
