# Roundcube lmr/duo_auth

[![Version](https://img.shields.io/badge/version-2.0.3-blue.svg)](https://github.com/leonardomarino/duo_auth)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D7.4-purple.svg)](https://php.net)

This is a Roundcube webmail plugin that enables [Duo Security](https://duo.com) Two Factor Authentication using the modern Universal Prompt.

![image](https://duo.com/assets/img/documentation/duoweb/websdk_network_diagram.png)

It redirects to Duo's secure authentication page after successful username/password authentication, requiring a 2nd Factor of Authentication using Duo Security (push, SMS, call, hardware token code).

## 🚀 What's New in v2.0.3

- **Duo Universal Prompt** - Modern, accessible authentication experience
- **Enhanced Security** - OIDC/OAuth 2.0 based authentication flow
- **Flexible Bypass System** - Three-tier bypass logic (global user, global IP, conditional)
- **IPv4/IPv6 Support** - Full CIDR notation support for IP whitelisting
- **Proxy Detection** - Configurable proxy header trust
- **Failmode Options** - Choose between secure (block) or open (allow) on Duo service failure
- **Comprehensive Logging** - Configurable log levels for debugging
- **PHP 8.2 Ready** - Full compatibility with modern PHP versions

## INSTALLATION
============

### Prerequisites

- PHP 7.4 or higher (PHP 8.x supported)
- Roundcube 1.4.0 or higher
- Composer
- Duo Security account with Admin API access

### Install via Composer

From the root directory of your Roundcube installation:
```bash
# Update Composer
composer update

# Install the plugin
composer require "lmr/duo_auth:^2.0"

# Or for manual installation
cd plugins/
git clone https://github.com/leonardomarino/duo_auth.git
cd duo_auth
composer install
```

### Quick Setup

Run the installation script:
```bash
cd plugins/duo_auth/
php bin/install.php
```

## CONFIGURATION
=============

### 1. Configure Duo Settings

Copy and edit the configuration file:
```bash
cp config.inc.php.dist config.inc.php
nano config.inc.php
```

Update with your Duo credentials from the [Duo Admin Panel](https://admin.duosecurity.com):
```php
// Required settings
$config['duo_client_id'] = 'YOUR_CLIENT_ID';
$config['duo_client_secret'] = 'YOUR_CLIENT_SECRET';
$config['duo_api_hostname'] = 'api-xxxxxxxx.duosecurity.com';
$config['duo_redirect_uri'] = 'https://your-domain.com/roundcube/?_task=login&_action=plugin.duo_callback';

// Optional: Bypass settings
$config['duo_bypass_users'] = ['service_account'];  // Users who always skip Duo
$config['duo_bypass_ips'] = ['192.168.1.0/24'];    // IPs where everyone skips Duo
$config['duo_bypass_rules'] = [                     // Conditional bypasses
    'admin' => ['127.0.0.1', '::1'],
];
```

### 2. Enable in Roundcube

Add to your Roundcube configuration (`config/config.inc.php`):
```php
$config['plugins'] = ['duo_auth', /* other plugins */];
$config['session_storage'] = 'php';
```

### 3. Configure PHP Session

Ensure your `php.ini` has:
```ini
session.save_handler = files
session.save_path = "/var/lib/php/sessions"
```

## MIGRATION FROM v1.x
==================

If upgrading from the legacy iframe-based version:

1. **Update Duo Application** in Duo Admin Panel for Universal Prompt
2. **Update Configuration Format**:
   - Old: `duo_auth.conf` → New: `config.inc.php`
   - `ikey` → `duo_client_id`
   - `skey` → `duo_client_secret`
   - `host` → `duo_api_hostname`
3. **Test with** `duo_failmode = 'open'` first
4. **Switch to** `duo_failmode = 'secure'` after verification

## FEATURES
========

### Three-Tier Bypass System

1. **Global User Bypass** - Specific users skip Duo from any location
2. **Global IP Bypass** - All users skip Duo from trusted networks
3. **Conditional Bypass** - Specific users from specific IPs only

### Advanced Options

- **Failmode** - Choose behavior when Duo service is unavailable
- **Session Timeout** - Configurable Duo session duration
- **Proxy Support** - Trust headers from reverse proxies
- **Debug Logging** - Detailed logs for troubleshooting

## TROUBLESHOOTING
===============

### Check Logs
```bash
tail -f plugins/duo_auth/logs/duo_auth.log
```

### Test Configuration
```bash
cd plugins/duo_auth/
php -l duo_auth.php
composer validate
```

### Common Issues

| Problem | Solution |
|---------|----------|
| 500 Error | Check PHP error logs, ensure Composer dependencies installed |
| "Client ID not found" | Verify credentials in `config.inc.php` |
| Bypass not working | Check IP detection, enable debug logging |
| Session timeout | Adjust `duo_session_timeout` in config |

## CREDITS
=======

**Author:** Alexios Polychronopoulos - Original duo_auth for Roundcube

**Author:** Leonardo Mariño-Ramírez - Updated for Roundcube 1.3.0+ compatibility, v2.0.0 Universal Prompt migration

**Author:** Johnson Chow - Added IPv4 CIDR matching and user-specific 2FA override

**Author:** Pavlo Lyha - Rewrote plugin for Duo Web v4 SDK compatibility

## LICENSE
=======

This project is licensed under the GPL-3.0-or-later License - see the [LICENSE](LICENSE) file for details.

## SUPPORT
=======

- **Issues:** [GitHub Issues](https://github.com/leonardomarino/duo_auth/issues)
- **Wiki:** [Documentation](https://github.com/leonardomarino/duo_auth/wiki)
- **Duo Docs:** [Duo Universal Prompt Guide](https://duo.com/docs/universal-prompt-update-guide)

## CHANGELOG
=========

### v2.0.2 (2025)
- Complete rewrite for Duo Universal Prompt (Web SDK v4)
- Added three-tier bypass system
- IPv4/IPv6 with CIDR support
- Proxy detection and failmode
- Configuration moved to config.inc.php
- PHP 8.2 compatibility

### v1.0.9 (2023)
- Initial Duo Web v4 SDK support by Pavlo Lyha

### v1.0.8 (2023)
- IPv4 CIDR matching by Johnson Chow
- User-specific 2FA override

### v1.0.3 (2020)
- Roundcube 1.3.0 compatibility by Leonardo Mariño-Ramírez

### v1.0.0 (2019)
- Initial release by Alexios Polychronopoulos

---

**⚠️ Important:** The traditional Duo Prompt (iframe-based) reached end of support on March 30, 2024. All installations must use Universal Prompt (SDK v4).
