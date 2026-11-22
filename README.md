# Roundcube lmr/duo_auth

[![Version](https://img.shields.io/badge/version-2.0.9-blue.svg)](https://github.com/leonardomarino/duo_auth)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-purple.svg)](https://php.net)

This is a Roundcube webmail plugin that enables [Duo Security](https://duo.com) Two Factor Authentication using the modern Universal Prompt.

![image](https://duo.com/assets/img/documentation/duoweb/websdk_network_diagram.png)

It redirects to Duo's secure authentication page after successful username/password authentication, requiring a 2nd Factor of Authentication using Duo Security (push, SMS, call, hardware token code).

## What's New in v2.0.9

Security hardening release — all users should upgrade. See [CHANGELOG.md](CHANGELOG.md) for details and **upgrade notes** (manual installs: delete `plugins/duo_auth/vendor/` and run `composer install --no-dev`).

- **No Roundcube copy in the web root** - manual installs no longer pull a full Roundcube into `plugins/duo_auth/vendor/`; a new `.htaccess` denies `vendor/`, `bin/` and `tests/`
- **Configuration errors always fail secure** - `duo_failmode = 'open'` now applies only when Duo is unreachable
- **Idle timeout** - `duo_session_timeout` resets on activity instead of logging everyone out 15 minutes after login
- **Hardening** - constant-time state check, log-injection protection, optional bypass notice (`duo_msg_bypass = ''`)
- **Packaging** - no PHP platform pin (correct dependencies on PHP 8.0/8.1); `duo_timeout` template default 300s
- **CI** - read-only token, actions pinned to commit SHAs

v2.0.7 closed several Duo bypasses ([GHSA-3xg2-jq85-4qfg](https://github.com/leonardomarino/duo_auth/security/advisories/GHSA-3xg2-jq85-4qfg)); upgrade from v2.0.6 or earlier.

## Installation

### Prerequisites

- PHP 8.0 or higher
- Roundcube 1.6.0 or higher
- Composer
- A Duo account with a **Web SDK** application (Duo Admin Panel → Applications → Protect an Application → Web SDK), which provides the Client ID, Client Secret and API hostname

### Install via Composer

From the root directory of your Roundcube installation:

```bash
# 1. Allow the plugin installer
composer config allow-plugins.roundcube/plugin-installer true

# 2. Install the plugin
composer require "lmr/duo_auth:^2.0"
```

### Manual installation

```bash
cd plugins/
git clone https://github.com/leonardomarino/duo_auth.git
cd duo_auth
composer install --no-dev
```

`--no-dev` keeps test and lint tools out of `vendor/`.

On the Roundcube 1.6 layout (document root = Roundcube root), the plugin directory is web-accessible, and Roundcube's own `.htaccess` only blocks the top-level `vendor/`. The plugin ships a `.htaccess` that denies `vendor/`, `bin/` and `tests/` on Apache (needs `AllowOverride FileInfo` or `All`). On nginx, add:

```nginx
location ~ ^/plugins/[^/]+/(vendor|bin|tests)/ {
    deny all;
}
```

Installs that use Roundcube's `public_html/` document root (the 1.7 layout) only serve plugin static files and aren't affected.

Then enable the plugin by adding `'duo_auth'` to `$config['plugins']` in Roundcube's `config/config.inc.php`.

## Configuration

### 1. Create the configuration file

Both install methods create `plugins/duo_auth/config.inc.php` from `config.inc.php.dist`, but with different permissions: the manual `composer install --no-dev` uses mode `0640`, while `composer require` (via Roundcube's plugin installer) uses your default umask, often `0644`. Either way, restrict it, since it holds the client secret:

```bash
cd plugins/duo_auth/
[ -f config.inc.php ] || cp config.inc.php.dist config.inc.php
chmod 0640 config.inc.php
sudo chown root:www-data config.inc.php   # use your web server's group
```

`bin/install.php` checks prerequisites, creates the file if needed, and warns about missing settings or unsafe permissions.

### 2. Duo credentials

From the [Duo Admin Panel](https://admin.duosecurity.com):

```php
$config['duo_client_id'] = 'YOUR_CLIENT_ID';           // 20 characters
$config['duo_client_secret'] = 'YOUR_CLIENT_SECRET';   // 40 characters
$config['duo_api_hostname'] = 'api-xxxxxxxx.duosecurity.com';
$config['duo_redirect_uri'] = 'https://your-domain.com/roundcube/?_task=login&_action=plugin.duo_callback';
```

`duo_redirect_uri` must match the redirect URI configured for the application in Duo exactly.

### 3. Bypass rules (optional)

Usernames are matched case-insensitively. IP entries accept single addresses or CIDR ranges (IPv4 and IPv6); malformed ranges and `/0` are ignored and logged.

```php
$config['duo_bypass_users'] = ['service_account'];  // Users who always skip Duo
$config['duo_bypass_ips'] = ['192.168.1.0/24'];     // IPs where everyone skips Duo
$config['duo_bypass_rules'] = [                     // Specific users from specific IPs
    'admin' => ['192.168.1.10'],
];
```

### 4. Reverse proxy (optional)

If Roundcube is behind a reverse proxy or load balancer, the plugin sees the proxy's address unless you tell it which proxies to trust:

```php
$config['duo_trust_proxy_headers'] = true;
$config['duo_trusted_proxies'] = ['127.0.0.1'];     // Your proxy's IP(s) or CIDR range(s)
$config['duo_proxy_header'] = 'X-Forwarded-For';    // Or 'X-Real-IP', 'CF-Connecting-IP'
```

Headers are honored only when the request comes directly from a trusted proxy, and are read right-to-left so client-supplied entries are ignored. Make sure your proxy overwrites or appends to the header rather than passing a client value through.

### Security notes

- Behind a reverse proxy, do not put the proxy's address (often `127.0.0.1`) in any bypass list: every request comes from it. Configure the proxy settings above instead.
- Keep `duo_failmode = 'secure'` in production. With `'open'`, anyone who can stop the server reaching Duo bypasses 2FA. (`'open'` only applies when Duo is unreachable; configuration errors always block login.)
- Set `duo_msg_bypass = ''` to hide the "bypassed" notice, which otherwise tells users (and attackers) that a bypass rule matched.
- Set Roundcube's `$config['ip_check'] = true;` to bind sessions to the client IP. `duo_callback_ip_check` does the same for the Duo login step.
- `config.inc.php` contains `duo_client_secret`: keep it at mode `0640`, owned by `root:<web server group>`.
- In the Duo Admin Panel, set the application's **New User Policy** to **Deny**. Usernames are lowercased before being sent to Duo; if your IMAP server accepts other variants (e.g. with and without `@domain`), make sure each maps to an enrolled Duo user or is rejected.

## Upgrading

### From v2.0.6 or earlier

See the **Upgrade notes** for 2.0.7 in [CHANGELOG.md](CHANGELOG.md). In short:

- If `duo_trust_proxy_headers = true`, list your proxy in `duo_trusted_proxies` (and set `duo_proxy_header` if it isn't `X-Forwarded-For`), or proxy headers are ignored.
- Remove `127.0.0.1` from `duo_bypass_ips` unless you are certain no local proxy sits in front of Roundcube.

### From v1.x

If upgrading from the legacy iframe-based version:

1. **Create a Web SDK application** in the Duo Admin Panel for the Universal Prompt
2. **Update the configuration format**:
   - Old: `duo_auth.conf` → New: `config.inc.php`
   - `ikey` → `duo_client_id`
   - `skey` → `duo_client_secret`
   - `host` → `duo_api_hostname`
3. **Verify on a test instance first.** `duo_failmode = 'open'` can help while testing connectivity, but never use it in production
4. **Use** `duo_failmode = 'secure'` in production

## Features

### Three-Tier Bypass System

Checked in this order:

1. **Global User Bypass** - Specific users skip Duo from any location
2. **Global IP Bypass** - All users skip Duo from trusted networks
3. **Conditional Bypass** - Specific users from specific IPs only

### Advanced Options

- **Failmode** - Choose behavior when the Duo service is unavailable (`secure` or `open`)
- **Idle Timeout** - `duo_session_timeout` logs users out after that many seconds without activity (default 15 minutes)
- **Reverse Proxy Support** - Trusted-proxy allowlist and a single configurable client-IP header
- **Callback IP Check** - Optionally require the Duo callback to come from the login IP
- **Debug Logging** - Detailed logs for troubleshooting (`duo_log_level = 'debug'`)

## Troubleshooting

### Check Logs

The plugin logs through Roundcube's log driver as `duo_auth`. With the default file driver, from the Roundcube root:

```bash
tail -f logs/duo_auth.log
```

### Test Configuration

```bash
cd plugins/duo_auth/
php bin/install.php
php -l duo_auth.php
composer validate
```

### Common Issues

| Problem | Solution |
|---------|----------|
| 500 Error | Check PHP error logs, ensure Composer dependencies are installed |
| "Two-factor authentication service is unavailable" | Check `duo_auth.log`. "Unable to connect to Duo" means the server can't reach `duo_api_hostname` |
| "Duo configuration error" in the log | "The Client ID is invalid" / "The Client Secret is invalid" means the credentials in `config.inc.php` are wrong (IDs are 20 characters, secrets 40) |
| "Two-factor authentication is not configured correctly" | Credentials are missing or invalid, or the web server can't read `config.inc.php` (mode `0640`): `chown root:<web server group> config.inc.php`. This blocks login even with `duo_failmode = 'open'` |
| Bypass not working | Enable debug logging and check the detected client IP. Behind a proxy, configure `duo_trusted_proxies`; look for "Ignoring invalid or match-all CIDR range" warnings |
| Logged out after a period of inactivity | Adjust `duo_session_timeout` (idle timeout) and Roundcube's `session_lifetime` |
| Duo prompt times out | Users must finish the prompt within `duo_timeout` seconds (default 300) |

## Credits

**Author:** Alexios Polychronopoulos - Original duo_auth for Roundcube

**Author:** Leonardo Mariño-Ramírez - Updated for Roundcube 1.3.0+ compatibility, v2.0.0 Universal Prompt migration

**Author:** Johnson Chow - Added IPv4 CIDR matching and user-specific 2FA override

**Author:** Pavlo Lyha - Rewrote plugin for Duo Web v4 SDK compatibility

## License

This project is licensed under the GPL-3.0-or-later License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues:** [GitHub Issues](https://github.com/leonardomarino/duo_auth/issues)
- **Wiki:** [Documentation](https://github.com/leonardomarino/duo_auth/wiki)
- **Duo Docs:** [Duo Universal Prompt Guide](https://duo.com/docs/universal-prompt-update-guide)

## Changelog

Full details in [CHANGELOG.md](CHANGELOG.md).

### v2.0.9 (2026-11-21)
- Security: manual installs no longer place a Roundcube copy in the web root; `.htaccess` denies `vendor/`, `bin/`, `tests/`
- Config errors fail secure regardless of failmode; idle `duo_session_timeout`; constant-time state check; log-injection protection; optional bypass notice
- Composer platform pin removed; `duo_timeout` template default 300s; CI least-privilege and SHA-pinned actions

### v2.0.8 (2026-11-21)
- Documentation: README restructured and corrected; `config.inc.php.dist` comment for `duo_timeout` corrected

### v2.0.7 (2026-11-21)
- Security: Duo bypasses closed (`_url` username injection, spoofable proxy headers, default `127.0.0.1` bypass, match-all malformed CIDR)
- Usernames canonicalized; Duo approval bound to user; optional callback IP check; login-task action guard
- Installer/config hardening (`0640` config, no web-root `logs/`, failmode warning)
- Duo Universal SDK `^1.2.0`; CI no longer masks test failures

### v2.0.6 (2026-04-11)
- IPv4-mapped IPv6 normalization in `get_client_ip()` for dual-stack CIDR bypass correctness
- CIDR prefix length bounds checks in `ip_in_cidr()` (max 32 for IPv4, 128 for IPv6)
- `startup()` callback exemption scoped to login task only
- Proactive `duo_state` cleanup on login page early-return
- Redundant `cleanup_duo_session()` calls removed from `callback_handler()` catch blocks

### v2.0.5 (2026-01-29)
- Security fix: back-button bypass — startup hook enforces Duo completion on every request

### v2.0.4 (2025-11-20)
- Complete rewrite for Duo Universal Prompt (Web SDK v4)
- Added three-tier bypass system
- IPv4/IPv6 with CIDR support
- Proxy detection and failmode
- Configuration moved to config.inc.php
- PHP 8.2 compatibility

### v1.0.9 (2023-06-15)
- Initial Duo Web v4 SDK support by Pavlo Lyha

### v1.0.8 (2023-05-22)
- IPv4 CIDR matching by Johnson Chow
- User-specific 2FA override

### v1.0.3 (2017-08-30)
- Roundcube 1.3.0 compatibility by Leonardo Mariño-Ramírez

### v1.0.0 (2019)
- Initial release by Alexios Polychronopoulos

---

**⚠️ Important:** The traditional Duo Prompt (iframe-based) reached end of support on March 30, 2024. All installations must use Universal Prompt (SDK v4).
