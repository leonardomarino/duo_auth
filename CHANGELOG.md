# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.6] - 2026-04-11

### Fixed

- IPv4-mapped IPv6 normalization in `get_client_ip()` — dual-stack deployments (PHP-FPM/Apache) no longer silently fail CIDR bypass matching when `REMOTE_ADDR` is presented as `::ffff:x.x.x.x`
- CIDR prefix bounds validation in `ip_in_cidr()` — invalid prefix lengths (e.g. `/200` on an IPv6 range) now return `false` immediately rather than producing undefined index behavior in the byte loop
- `startup()` callback exemption tightened — the `plugin.duo_callback` action exemption is now scoped to the login task, closing a surface where a crafted `_action` parameter on a non-login task could suppress the pending-auth guard
- Redundant `cleanup_duo_session()` calls removed from `callback_handler()` catch blocks — `fail_login()` is now the sole authoritative caller on error paths
- `duo_state` is now cleared immediately when the user returns to the login page, rather than persisting until the next protected-task request

## [2.0.5] - 2026-01-29

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

## [2.0.4] - 2025-11-20

### Added

- Complete rewrite for Duo Universal Prompt (Web SDK v4)
- Three-tier bypass system (global user, global IP, conditional user+IP)
- IPv4/IPv6 CIDR support for IP whitelisting
- Proxy header detection for client IP and failmode options
- Configuration moved to `config.inc.php`
- PHP 8.2 compatibility

### Changed

- Migrated from deprecated Duo Web SDK v2 to Universal Prompt

### Removed

- Legacy iframe-based Duo prompt
- Duo Web SDK v2 dependencies

## [1.0.9] - 2023-06-15

### Added

- Initial Duo Web v4 SDK support (contributed by Pavlo Lyha)

## [1.0.8] - 2023-05-22

### Added

- IPv4 CIDR matching (contributed by Johnson Chow)
- User-specific 2FA override

## [1.0.3] - 2017-08-30

### Changed

- Roundcube 1.3.0 compatibility (contributed by Leonardo Mariño-Ramírez)

## [1.0.0] - 2019

### Added

- Initial release (Alexios Polychronopoulos)
