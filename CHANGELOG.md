# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Removed `config.platform.php` (`8.2.0`) from `composer.json`. It made `composer install` inside the plugin directory (the manual install) resolve dependencies as if running PHP 8.2, so PHP 8.0/8.1 servers could get packages they can't run. Dependencies now resolve for the PHP version actually in use. Installs via `composer require` from the Roundcube root were not affected. CI no longer needs its per-matrix override.

## [2.0.8] - 2026-11-21

Documentation-only release; no code changes.

### Changed

- README restructured for consistency: fixed broken heading underlines, split Composer and manual install, documented the reverse-proxy settings (`duo_trusted_proxies`, `duo_proxy_header`) and `config.inc.php` permissions for both install paths, added upgrade notes for v2.0.6 and earlier, and aligned changelog dates with this file.
- README: the prerequisite is a Duo **Web SDK** application, not Admin API access.
- README: the v1.x migration steps no longer suggest `duo_failmode = 'open'` outside a test instance.
- README: removed the `session.save_handler = files` advice; Roundcube uses its own session handler.
- README: troubleshooting entries now quote the Duo SDK's actual error messages.
- `config.inc.php.dist`: `duo_timeout` is the window for completing the Duo prompt, not an API call timeout.

## [2.0.7] - 2026-11-21

### Security

- **CRITICAL**: The username used for Duo and for bypass checks could be chosen by the attacker. `login_after` hook args are built from the client-supplied `_url` POST field, and `get_username()` read `$args['user']` first, so `_url=user=<bypass user>` skipped Duo entirely, and `_url=user=<attacker's Duo user>` let an attacker approve the prompt on their own device. The username now comes only from the Roundcube user record (falling back to `$_SESSION['username']`); the raw `_user` POST fallback was removed too.
- **CRITICAL**: Proxy headers could be spoofed to match `duo_bypass_ips`. `duo_trusted_proxies` was never checked, five headers were read, and the left-most (client-controlled) `X-Forwarded-For` entry was used. Headers are now honored only when `REMOTE_ADDR` is a trusted proxy, only the single header named by the new `duo_proxy_header` option is read, and it is walked right-to-left skipping trusted hops.
- **CRITICAL**: `config.inc.php.dist` no longer ships `127.0.0.1` in `duo_bypass_ips`. Behind a same-host reverse proxy every request has that `REMOTE_ADDR`, so all users skipped Duo.
- Malformed CIDR ranges (`10.0.0.0/`, `10.0.0.0/abc`) were cast to prefix `/0` and matched every address. Non-numeric, missing and `/0` prefixes are now rejected and logged.
- Usernames are canonicalized (trimmed, lowercased) before bypass matching and before being sent to Duo, so case variants accepted by IMAP map to a single Duo identity.
- `startup()` no longer lets every `_task=login` action through. Only the bare login page, the login POST and the Duo callback are exempt; other plugins' login-task actions now require completed Duo for logged-in sessions (anonymous visitors are unaffected).

- A completed Duo approval is now bound to the user it was issued for: `is_duo_authenticated()` discards a `duo_authenticated` record whose username doesn't match the logged-in user.
- New `duo_callback_ip_check` option (default `false`) rejects the Duo callback if it comes from a different client IP than the password login. The README now recommends Roundcube's `ip_check`.
- `config.inc.php.dist` warns that `duo_failmode = 'open'` turns every login into password-only for anyone who can cut the server off from Duo.
- `bin/install.php` now creates `config.inc.php` with mode `0640` (was `0644`, despite the comment saying "not world-readable"), prints a `chown root:<web group>` hint, and warns if an existing config is world-readable. Composer's `post-install-cmd` also sets `0640`.
- `bin/install.php` no longer creates a `logs/` directory inside the plugin (and web root). The plugin logs through Roundcube's log driver, so that directory was unused.

### Upgrade notes

- If you set `duo_trust_proxy_headers = true`, you must now list your proxy in `duo_trusted_proxies` (IP or CIDR), and set `duo_proxy_header` if it isn't `X-Forwarded-For`. Otherwise headers are ignored and `REMOTE_ADDR` is used.
- If your `config.inc.php` was copied from an older template, remove `127.0.0.1` from `duo_bypass_ips` unless you are certain no local proxy sits in front of Roundcube.
- `config.inc.php` created by the installer or Composer is mode `0640`. If the web server is not the file's owner or group, it can't read the config and logins are blocked (`secure`) until you `chown root:<web group> config.inc.php`.
- You can delete any `plugins/duo_auth/logs/` directory left by the old installer.
- Usernames sent to Duo are now lowercase. In the Duo Admin Panel, set the application's **New User Policy** to **Deny** so unenrolled username variants cannot self-enroll.

### Changed

- Require `duosecurity/duo_universal_php` `^1.2.0` (was `^1.0.2`). 1.1.0 added Duo's new certificate authorities; older SDKs can fail TLS to Duo (blocking logins in `secure` mode). 1.2.0 also stops falling back to the OS certificate store when CA pinning is enabled.
- CI resolves dependencies for each matrix PHP version and fails the build when PHPUnit fails.

### Fixed

- Test bootstrap autoloaded the real Roundcube classes from `vendor/`, so the mocks were never defined and the whole suite errored.

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
