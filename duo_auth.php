<?php
/**
 * Duo Security Plugin for Roundcube
 * Version: 2.0.7
 *
 * Supports: Global User Bypass, Global IP Bypass, and User-Specific IP Bypass
 * Features: IPv4/IPv6 support, Proxy detection, Failmode, Comprehensive logging
 *
 * Security: server-side username only, trusted-proxy IP resolution, strict CIDR,
 *           Duo approval bound to the logged-in user
 */

declare(strict_types=1);

use Duo\DuoUniversal\Client;
use Duo\DuoUniversal\DuoException;

class duo_auth extends rcube_plugin
{
    private rcube $rc;
    private bool $debug_mode = false;
    
    /**
     * Plugin initialization
     */
    public function init(): void
    {
        $this->rc = rcube::get_instance();
        $this->load_config();
        
        // Set debug mode from config
        $this->debug_mode = $this->rc->config->get('duo_log_level') === 'debug';
        
        // Register hooks
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('login_after', [$this, 'login_after']);
        $this->add_hook('logout_after', [$this, 'logout_after']);
        
        // Register callback action
        $this->register_action('plugin.duo_callback', [$this, 'callback_handler']);
        
        $this->log('info', 'Duo Auth plugin initialized');
    }

    /**
     * SECURITY FIX: Startup hook to check for incomplete Duo authentication
     * 
     * This prevents the back-button bypass where a user could:
     * 1. Login with username/password (session created)
     * 2. Get redirected to Duo
     * 3. Press browser back button without completing Duo
     * 4. Return to an authenticated session
     * 
     * This hook runs on every request and ensures that if Duo auth was initiated,
     * it must be completed before the user can access any resources.
     */
    public function startup(array $args): array
    {
        // Skip check for login task and duo callback action
        $task = $this->rc->task ?? '';
        $action = $this->rc->action ?? '';
        
        // Allow the callback handler to process — scoped to login task only
        if ($action === 'plugin.duo_callback' && ($task === 'login' || $task === '')) {
            return $args;
        }

        // Allow the bare login page; proactively clear any stale pending state.
        // Other login-task actions (e.g. from other plugins) fall through to the
        // checks below so a password-only session cannot reach them.
        if ($task === 'login' && $action === '') {
            $this->cleanup_duo_session();
            return $args;
        }
        
        // Check if Duo auth was initiated but not completed
        if ($this->is_duo_auth_pending()) {
            $username = $_SESSION['duo_user'] ?? 'unknown';
            $this->log('warning', "SECURITY: Incomplete Duo auth detected for user '$username' - forcing logout");
            
            // Clear the pending state
            $this->cleanup_duo_session();
            
            // Force logout
            $this->rc->kill_session();
            
            // Redirect to login with error message
            $this->rc->output->show_message(
                $this->rc->config->get('duo_msg_incomplete', 'Two-factor authentication was not completed. Please login again.'),
                'error'
            );
            $this->rc->output->redirect(['_task' => 'login']);
            exit;
        }
        
        // For authenticated sessions, verify Duo was completed. The login form
        // POST is exempt: Roundcube kills any existing session before re-login.
        $is_login_post = ($task === 'login' && $action === 'login');
        if (!$is_login_post && $this->rc->user && $this->rc->user->ID) {
            // User appears logged in - check if Duo is required and was completed
            if (!$this->is_duo_authenticated() && $this->is_duo_required_for_session()) {
                $username = $this->rc->user->get_username() ?? 'unknown';
                $this->log('warning', "SECURITY: User '$username' logged in without Duo verification - forcing logout");
                
                $this->rc->kill_session();
                $this->rc->output->show_message(
                    $this->rc->config->get('duo_msg_required', 'Two-factor authentication is required.'),
                    'error'
                );
                $this->rc->output->redirect(['_task' => 'login']);
                exit;
            }
        }
        
        return $args;
    }

    /**
     * Check if Duo authentication is pending (started but not completed)
     */
    private function is_duo_auth_pending(): bool
    {
        // If we have duo_state but no duo_authenticated, auth was started but not finished
        return isset($_SESSION['duo_state']) && 
               isset($_SESSION['duo_user']) && 
               !isset($_SESSION['duo_authenticated']);
    }

    /**
     * Check if Duo should be required for the current session
     * Returns false if user would be bypassed anyway
     */
    private function is_duo_required_for_session(): bool
    {
        // Check if Duo is enabled at all
        if (!$this->rc->config->get('duo_enabled', true)) {
            return false;
        }
        
        $username = $this->get_username();
        $user_ip = $this->get_client_ip();
        
        // Check global user bypass
        if ($username && in_array($username, $this->get_bypass_users(), true)) {
            return false;
        }
        
        // Check global IP bypass
        $global_ips = $this->rc->config->get('duo_bypass_ips', []);
        if ($this->is_ip_whitelisted($user_ip, $global_ips)) {
            return false;
        }
        
        // Check conditional bypass
        if ($username && $this->is_ip_whitelisted($user_ip, $this->get_bypass_rule_ips($username))) {
            return false;
        }
        
        // Duo is required
        return true;
    }

    /**
     * Handle post-login Duo authentication
     */
    public function login_after(array $args): array
    {
        // Check if Duo is enabled
        $enabled = $this->rc->config->get('duo_enabled', true);
        $this->log('debug', "Duo enabled status: " . ($enabled ? 'yes' : 'no'));
        
        if (!$enabled) {
            $this->log('info', 'Duo authentication disabled by configuration');
            return $args;
        }

        // Get username from various possible sources
        $username = $this->get_username();
        if (!$username) {
            $this->log('error', 'Unable to determine username for Duo auth');
            return $args;
        }
        
        // Get client IP with proxy support
        $user_ip = $this->get_client_ip();
        
        $this->log('info', "Login attempt - User: $username, IP: $user_ip");
        
        // Check if already authenticated in this session
        if ($this->is_duo_authenticated()) {
            $this->log('debug', 'User already Duo authenticated in this session');
            return $args;
        }

        // ====================================================================
        // BYPASS LOGIC
        // ====================================================================
        
        // 1. Global User Bypass (User skips Duo from any location)
        if (in_array($username, $this->get_bypass_users(), true)) {
            $this->log('info', "Bypassing Duo: Global user bypass for '$username'");
            $this->set_duo_authenticated($username, 'global_user_bypass');
            $this->show_bypass_message();
            return $args;
        }

        // 2. Global IP Bypass (All users skip Duo from these IPs)
        $global_ips = $this->rc->config->get('duo_bypass_ips', []);
        if ($this->is_ip_whitelisted($user_ip, $global_ips)) {
            $this->log('info', "Bypassing Duo: Global IP bypass for IP '$user_ip'");
            $this->set_duo_authenticated($username, 'global_ip_bypass');
            $this->show_bypass_message();
            return $args;
        }

        // 3. Conditional Bypass (Specific user from specific IP)
        $allowed_ips = $this->get_bypass_rule_ips($username);
        if (!empty($allowed_ips)) {
            if ($this->is_ip_whitelisted($user_ip, $allowed_ips)) {
                $this->log('info', "Bypassing Duo: Conditional bypass for '$username' from IP '$user_ip'");
                $this->set_duo_authenticated($username, 'conditional_bypass');
                $this->show_bypass_message();
                return $args;
            }
            $this->log('debug', "User '$username' has conditional rules but IP '$user_ip' not in allowed list");
        }

        // ====================================================================
        // DUO AUTHENTICATION REQUIRED
        // ====================================================================
        
        $this->log('info', "Duo authentication required for user '$username' from IP '$user_ip'");
        
        try {
            // Initialize Duo client
            $duo_client = $this->get_duo_client();
            
            // Health check with failmode support
            try {
                $health = $duo_client->healthCheck();
                if ($health['stat'] !== 'OK') {
                    throw new DuoException("Duo Health Check Failed: " . json_encode($health));
                }
                $this->log('debug', 'Duo health check passed');
            } catch (Exception $e) {
                $this->log('error', "Duo Health Check Error: " . $e->getMessage());
                
                // Check failmode setting
                $failmode = $this->rc->config->get('duo_failmode', 'secure');
                if ($failmode === 'open') {
                    $this->log('warning', "FAILMODE OPEN: Allowing login without Duo due to service unavailability");
                    $this->rc->output->show_message(
                        $this->rc->config->get('duo_msg_unavailable', 'Two-factor authentication unavailable - proceeding without'),
                        'warning'
                    );
                    $this->set_duo_authenticated($username, 'failmode_open');
                    return $args;
                } else {
                    $this->log('error', "FAILMODE SECURE: Blocking login due to Duo unavailability");
                    $this->fail_login($this->rc->config->get(
                        'duo_msg_unavailable',
                        'Two-factor authentication service is unavailable. Please try again later.'
                    ));
                }
            }

            // Generate state for CSRF protection
            $state = $duo_client->generateState();
            
            // Store session data - this marks auth as "pending"
            $_SESSION['duo_state'] = $state;
            $_SESSION['duo_user'] = $username;
            $_SESSION['duo_ip'] = $user_ip;
            $_SESSION['duo_timestamp'] = time();
            
            $this->log('debug', "Session data stored - State: " . substr($state, 0, 10) . "...");
            
            // Create Duo authentication URL
            $auth_url = $duo_client->createAuthUrl($username, $state);
            
            $this->log('info', "Redirecting user '$username' to Duo authentication");
            
            // Redirect to Duo
            $this->rc->output->redirect($auth_url);
            exit;

        } catch (DuoException $e) {
            $this->log('error', "Duo Exception: " . $e->getMessage());
            $this->handle_duo_error($e);
        } catch (Exception $e) {
            $this->log('error', "Unexpected Exception: " . $e->getMessage());
            $this->handle_duo_error($e);
        }
        
        return $args;
    }

    /**
     * Handle Duo callback after authentication
     */
    public function callback_handler(): void
    {
        $this->log('debug', 'Duo callback handler triggered');
        
        // Get callback parameters
        $code = rcube_utils::get_input_value('duo_code', rcube_utils::INPUT_GET);
        $state = rcube_utils::get_input_value('state', rcube_utils::INPUT_GET);
        
        // Retrieve saved session data
        $saved_state = $_SESSION['duo_state'] ?? null;
        $saved_user = $_SESSION['duo_user'] ?? null;
        $saved_ip = $_SESSION['duo_ip'] ?? null;
        $saved_time = $_SESSION['duo_timestamp'] ?? 0;
        
        $this->log('debug', "Callback data - Code present: " . ($code ? 'yes' : 'no') . 
                            ", State match: " . ($state === $saved_state ? 'yes' : 'no'));
        
        // Validate callback data
        if (!$code || !$state || !$saved_state || !$saved_user) {
            $this->log('error', 'Missing callback data');
            $this->fail_login('Security check failed: Missing authentication data.');
        }
        
        // Verify state matches (CSRF protection)
        if ($state !== $saved_state) {
            $this->log('error', 'State mismatch - possible CSRF attempt');
            $this->fail_login('Security check failed: Invalid state parameter.');
        }
        
        // Check for timeout (optional)
        $timeout = $this->rc->config->get('duo_timeout', 300); // 5 minutes default
        if ((time() - $saved_time) > $timeout) {
            $this->log('error', 'Duo authentication timeout');
            $this->fail_login('Authentication timeout. Please try again.');
        }

        // Optionally require the callback to come from the IP that started the login
        if ($this->rc->config->get('duo_callback_ip_check', false) && $this->get_client_ip() !== $saved_ip) {
            $this->log('error', "Callback IP " . $this->get_client_ip() . " does not match login IP '$saved_ip'");
            $this->fail_login('Security check failed: Network address changed during authentication.');
        }

        try {
            // Initialize Duo client
            $duo_client = $this->get_duo_client();
            
            // Exchange code for authentication result
            $this->log('debug', "Exchanging auth code for user '$saved_user'");
            $result = $duo_client->exchangeAuthorizationCodeFor2FAResult($code, $saved_user);
            
            // Log successful authentication
            $this->log('info', "Duo authentication successful for user '$saved_user' from IP '$saved_ip'");
            
            // Set authenticated flag
            $this->set_duo_authenticated($saved_user, 'duo_push');
            
            // Clean up session data
            $this->cleanup_duo_session();
            
            // Redirect to mail interface
            $this->rc->output->redirect(['_task' => 'mail']);

        } catch (DuoException $e) {
            $this->log('error', "Duo Callback Error: " . $e->getMessage());
            $this->fail_login($this->rc->config->get(
                'duo_msg_failed',
                'Two-factor authentication failed. Please try again.'
            ));
        } catch (Exception $e) {
            $this->log('error', "Unexpected Callback Error: " . $e->getMessage());
            $this->fail_login('An unexpected error occurred during authentication.');
        }
    }

    /**
     * Handle logout - cleanup Duo session data
     */
    public function logout_after(array $args): array
    {
        $this->log('debug', 'Logout handler - cleaning up Duo session');
        $this->cleanup_duo_session();
        unset($_SESSION['duo_authenticated']);
        return $args;
    }

    /**
     * Get Duo client instance
     */
    private function get_duo_client(): Client
    {
        $client_id = $this->rc->config->get('duo_client_id');
        $client_secret = $this->rc->config->get('duo_client_secret');
        $api_hostname = $this->rc->config->get('duo_api_hostname');
        $redirect_uri = $this->rc->config->get('duo_redirect_uri');
        
        if (!$client_id || !$client_secret || !$api_hostname || !$redirect_uri) {
            throw new Exception('Duo configuration incomplete. Please check config.inc.php');
        }
        
        return new Client(
            $client_id,
            $client_secret,
            $api_hostname,
            $redirect_uri
        );
    }

    /**
     * Get the authenticated username, canonicalized
     *
     * Only server-side sources are used. The login_after hook args are built
     * from the client-supplied _url POST field and must never be trusted.
     */
    private function get_username(): ?string
    {
        $username = null;
        if ($this->rc->user && $this->rc->user->ID) {
            $username = $this->rc->user->get_username();
        }
        if (!$username) {
            $username = $_SESSION['username'] ?? null;
        }
        return $this->normalize_username($username);
    }

    /**
     * Canonicalize a username (trim + lowercase) so case variants accepted by
     * the IMAP server map to one Duo identity and one bypass-list entry.
     */
    private function normalize_username(?string $username): ?string
    {
        $username = trim((string)$username);
        if ($username === '') {
            return null;
        }
        return function_exists('mb_strtolower') ? mb_strtolower($username, 'UTF-8') : strtolower($username);
    }

    /**
     * duo_bypass_users, normalized
     */
    private function get_bypass_users(): array
    {
        return array_filter(array_map(
            fn($u) => $this->normalize_username((string)$u),
            $this->rc->config->get('duo_bypass_users', [])
        ));
    }

    /**
     * IP list from duo_bypass_rules for a (normalized) username
     */
    private function get_bypass_rule_ips(string $username): array
    {
        $ips = [];
        foreach ($this->rc->config->get('duo_bypass_rules', []) as $user => $list) {
            if ($this->normalize_username((string)$user) === $username) {
                $ips = array_merge($ips, (array)$list);
            }
        }
        return $ips;
    }

    /**
     * Get client IP with proxy support
     *
     * Proxy headers are honored only when the direct peer (REMOTE_ADDR) is in
     * duo_trusted_proxies. The configured header is walked right-to-left,
     * skipping trusted proxy hops; the first untrusted hop is the client.
     * Left-most entries are client-controlled and are never trusted blindly.
     */
    private function get_client_ip(): string
    {
        $remote_addr = $this->normalize_ip($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

        if (!$this->rc->config->get('duo_trust_proxy_headers', false)) {
            return $remote_addr;
        }

        $trusted_proxies = $this->rc->config->get('duo_trusted_proxies', []);
        if (empty($trusted_proxies)) {
            $this->log('warning', 'duo_trust_proxy_headers is enabled but duo_trusted_proxies is empty - ignoring proxy headers');
            return $remote_addr;
        }

        if (!$this->is_ip_whitelisted($remote_addr, $trusted_proxies)) {
            $this->log('debug', "REMOTE_ADDR $remote_addr is not a trusted proxy - ignoring proxy headers");
            return $remote_addr;
        }

        // Accept either 'X-Forwarded-For' or 'HTTP_X_FORWARDED_FOR' style names
        $header = strtoupper(str_replace('-', '_', $this->rc->config->get('duo_proxy_header', 'X-Forwarded-For')));
        if (strpos($header, 'HTTP_') !== 0) {
            $header = 'HTTP_' . $header;
        }

        if (empty($_SERVER[$header])) {
            return $remote_addr;
        }

        $hops = array_reverse(array_map('trim', explode(',', $_SERVER[$header])));
        $ip = $remote_addr;
        foreach ($hops as $hop) {
            if (!filter_var($hop, FILTER_VALIDATE_IP)) {
                // A trusted proxy would not append garbage; stop at the last good hop
                $this->log('warning', "Invalid entry in $header - using last trusted hop");
                break;
            }
            $ip = $this->normalize_ip($hop);
            if (!$this->is_ip_whitelisted($ip, $trusted_proxies)) {
                break;
            }
        }

        $this->log('debug', "Client IP resolved via $header: $ip");
        return $ip;
    }

    /**
     * Normalize IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1 → 192.168.1.1)
     * so that IPv4 CIDR rules match correctly under dual-stack setups.
     */
    private function normalize_ip(string $ip): string
    {
        if (preg_match('/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i', $ip, $m)) {
            return $m[1];
        }
        return $ip;
    }

    /**
     * Check if IP is in whitelist (supports IPv4 and IPv6 with CIDR)
     */
    private function is_ip_whitelisted(?string $ip, array $whitelist): bool
    {
        if (empty($ip) || empty($whitelist)) {
            return false;
        }

        foreach ($whitelist as $range) {
            // Direct IP match
            if ($ip === $range) {
                $this->log('debug', "IP '$ip' matched directly with '$range'");
                return true;
            }
            
            // CIDR notation check
            if (strpos($range, '/') !== false) {
                if ($this->ip_in_cidr($ip, $range)) {
                    $this->log('debug', "IP '$ip' matched CIDR range '$range'");
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Check if IP is within CIDR range (IPv4 and IPv6 support)
     */
    private function ip_in_cidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr);
        // Reject malformed prefixes: (int) of '', 'abc' etc. is 0, which would
        // match every address. /0 is rejected too - use duo_enabled = false instead.
        if (count($parts) !== 2 || !ctype_digit($parts[1]) || (int)$parts[1] === 0) {
            $this->log('warning', "Ignoring invalid or match-all CIDR range '$cidr'");
            return false;
        }
        [$subnet, $bits] = $parts;
        $bits = (int)$bits;

        // IPv4
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
            filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if ($bits < 0 || $bits > 32) {
                return false;
            }
            $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));
            return (ip2long($ip) & $mask) === (ip2long($subnet) & $mask);
        }

        // IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) &&
            filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            if ($bits < 0 || $bits > 128) {
                return false;
            }
            $subnet_bin = inet_pton($subnet);
            $ip_bin     = inet_pton($ip);
            if ($subnet_bin === false || $ip_bin === false) {
                return false;
            }

            $bytes_to_check = intdiv($bits, 8);
            $bits_to_check  = $bits % 8;

            for ($i = 0; $i < $bytes_to_check; $i++) {
                if ($subnet_bin[$i] !== $ip_bin[$i]) {
                    return false;
                }
            }

            if ($bits_to_check > 0) {
                $mask = 0xFF << (8 - $bits_to_check);
                return (ord($subnet_bin[$bytes_to_check]) & $mask) ===
                       (ord($ip_bin[$bytes_to_check]) & $mask);
            }

            return true;
        }

        return false;
    }

    /**
     * Check if user is already Duo authenticated in this session
     */
    private function is_duo_authenticated(): bool
    {
        if (!isset($_SESSION['duo_authenticated'])) {
            return false;
        }
        
        $auth_data = $_SESSION['duo_authenticated'];

        // The Duo approval must belong to the user who is logged in now
        $current_user = $this->get_username();
        if ($current_user === null || ($auth_data['username'] ?? null) !== $current_user) {
            $this->log('warning', 'SECURITY: Duo authentication does not match the logged-in user - discarding');
            unset($_SESSION['duo_authenticated']);
            return false;
        }

        $timeout = $this->rc->config->get('duo_session_timeout', 900); // 15 minutes default
        
        // Check if authentication has timed out
        if (isset($auth_data['timestamp'])) {
            if ((time() - $auth_data['timestamp']) > $timeout) {
                $this->log('info', 'Duo authentication session expired');
                unset($_SESSION['duo_authenticated']);
                return false;
            }
        }
        
        return true;
    }

    /**
     * Set user as Duo authenticated
     */
    private function set_duo_authenticated(string $username, string $method): void
    {
        $_SESSION['duo_authenticated'] = [
            'username' => $username,
            'method' => $method,
            'timestamp' => time(),
            'ip' => $this->get_client_ip()
        ];
        
        $this->log('debug', "User '$username' marked as Duo authenticated via $method");
    }

    /**
     * Clean up Duo session data
     */
    private function cleanup_duo_session(): void
    {
        unset($_SESSION['duo_state']);
        unset($_SESSION['duo_user']);
        unset($_SESSION['duo_ip']);
        unset($_SESSION['duo_timestamp']);
    }

    /**
     * Handle Duo errors with failmode support
     */
    private function handle_duo_error(Exception $e): void
    {
        $failmode = $this->rc->config->get('duo_failmode', 'secure');
        
        if ($failmode === 'open') {
            $this->log('warning', "FAILMODE OPEN: Allowing login despite Duo error: " . $e->getMessage());
            $this->rc->output->show_message(
                $this->rc->config->get('duo_msg_unavailable', 'Two-factor authentication unavailable - proceeding without'),
                'warning'
            );
            // Don't exit, let login continue
        } else {
            $this->fail_login($this->rc->config->get(
                'duo_msg_unavailable',
                'Two-factor authentication service is unavailable.'
            ));
        }
    }

    /**
     * Fail login with message
     */
    private function fail_login(string $msg): never
    {
        $this->log('info', "Login failed: $msg");
        $this->cleanup_duo_session();
        $this->rc->kill_session();
        $this->rc->output->show_message($msg, 'error');
        $this->rc->output->redirect(['_task' => 'login']);
        exit;
    }

    /**
     * Show bypass message to user
     */
    private function show_bypass_message(): void
    {
        $msg = $this->rc->config->get('duo_msg_bypass', 'Two-factor authentication bypassed for this session.');
        $this->rc->output->show_message($msg, 'notice');
    }

    /**
     * Logging helper
     */
    private function log(string $level, string $message): void
    {
        if (!$this->rc->config->get('duo_log_enabled', true)) {
            return;
        }
        
        $log_level = $this->rc->config->get('duo_log_level', 'info');
        $levels = ['debug' => 0, 'info' => 1, 'warning' => 2, 'error' => 3];
        
        // Only log if message level >= configured level
        if (($levels[$level] ?? 1) >= ($levels[$log_level] ?? 1)) {
            $prefix = strtoupper($level);
            rcube::write_log('duo_auth', "[$prefix] $message");
        }
    }
}
