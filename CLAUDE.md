## Duo Auth Plugin Guide

## Build & Test Commands
- **Install Dependencies:** `composer install`
- **Validate Composer:** `composer validate`
- **Check Syntax (Lint):** `php -l duo_auth.php`
- **Check Config Syntax:** `php -l config.inc.php` (if exists)

## Deployment Patterns
- **Standard Install:** `composer require lmr/duo_auth` from Roundcube root.
- **Manual Install:** Clone into `plugins/duo_auth`, run `composer install` inside.
- **Enable Plugin:** Add `'duo_auth'` to `$config['plugins']` in Roundcube's `config/config.inc.php`.

## Code Style & Architecture
- **PHP Version:** >= 7.4 (8.2+ recommended).
- **Style:** Follow standard Roundcube plugin conventions (Hooks: `authenticate`, `login_after`, `render_page`).
- **Configuration:** Always use `config.inc.php` based on `config.inc.php.dist`.
- **Security Logic:** - The Duo session is stateful and relies on OIDC/OAuth 2.0.
    - **Back-Button Bypass Fix:** Ensure any redirect logic validates the Duo state before allowing access to the mailbox.
- **Logging:** Use the internal logging function which writes to `logs/duo_auth.log`. Level is configurable.

## Logic Flow: Three-Tier Bypass
1. **Global User Bypass:** Checked first. Matches against `duo_bypass_users`.
2. **Global IP Bypass:** Checked second. Matches `duo_bypass_ips` using CIDR (v4/v6).
3. **Conditional Bypass:** Checked third. Matches specific users from specific IPs in `duo_bypass_rules`.

## Error Handling
- **Failmode 'open':** Allows login if Duo API is unreachable (use for initial testing).
- **Failmode 'secure':** Blocks login if Duo API is unreachable (standard for production).


## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `python3 -c "from graphify.watch import _rebuild_code; from pathlib import Path; _rebuild_code(Path('.'))"` to keep the graph current
