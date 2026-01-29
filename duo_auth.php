<?php
/**
 * Duo Security Plugin for Roundcube
 * Version: 2.0.5
 * 
 * Supports: Global User Bypass, Global IP Bypass, and User-Specific IP Bypass
 * Features: IPv4/IPv6 support, Proxy detection, Failmode, Comprehensive logging
 * 
 * Security Fix: Added startup hook to prevent back-button bypass
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
        
        // Allow the callback handler to process
        if ($action === 'plugin.duo_callback') {
            return $args;
        }
        
        // Allow login page itself
        if ($task === 'login' && $action !== 'login') {
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
        
        // For authenticated sessions (non-login tasks), verify Duo was completed
        if ($task !== 'login' && $this->rc->user && $this->rc->user->ID) {
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
        
        $username = $this->rc->user ? $this->rc->user->get_username() : null;
        $user_ip = $this->get_client_ip();
        
        // Check global user bypass
        $global_users = $this->rc->config->get('duo_bypass_users', []);
        if ($username && in_array($username, $global_users, true)) {
            return false;
        }
        
        // Check global IP bypass
        $global_ips = $this->rc->config->get('duo_bypass_ips', []);
        if ($this->is_ip_whitelisted($user_ip, $global_ips)) {
            return false;
        }
        
        // Check conditional bypass
        $rules_map = $this->rc->config->get('duo_bypass_rules', []);
        if ($username && isset($rules_map[$username])) {
            if ($this->is_ip_whitelisted($user_ip, $rules_map[$username])) {
                return false;
            }
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
        $username = $this->get_username($args);
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
        $global_users = $this->rc->config->get('duo_bypass_users', []);
        if ($username && in_array($username, $global_users, true)) {
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
        $rules_map = $this->rc->config->get('duo_bypass_rules', []);
        if ($username && isset($rules_map[$username])) {
            $allowed_ips = $rules_map[$username];
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
            $this->cleanup_duo_session();
            $this->fail_login($this->rc->config->get(
                'duo_msg_failed',
                'Two-factor authentication failed. Please try again.'
            ));
        } catch (Exception $e) {
            $this->log('error', "Unexpected Callback Error: " . $e->getMessage());
            $this->cleanup_duo_session();
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
     * Get username from various sources
     */
    private function get_username(array $args): ?string
    {
        // Try various sources for username
        $username = $args['user'] ?? 
                   $args['username'] ?? 
                   $_SESSION['username'] ?? 
                   null;
        
        if (!$username) {
            $username = rcube_utils::get_input_value('_user', rcube_utils::INPUT_POST);
        }
        
        if (!$username && $this->rc->user && $this->rc->user->ID) {
            $username = $this->rc->user->get_username();
        }
        
        return $username;
    }

    /**
     * Get client IP with proxy support
     */
    private function get_client_ip(): string
    {
        $ip = '0.0.0.0';
        
        // Check if we should trust proxy headers
        $trust_proxy = $this->rc->config->get('duo_trust_proxy_headers', false);
        $trusted_proxies = $this->rc->config->get('duo_trusted_proxies', []);
        
        if ($trust_proxy) {
            // Check various proxy headers
            $proxy_headers = [
                'HTTP_CF_CONNECTING_IP',     // Cloudflare
                'HTTP_X_FORWARDED_FOR',       // Standard proxy
                'HTTP_X_REAL_IP',             // Nginx proxy
                'HTTP_CLIENT_IP',             // Some proxies
                'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster setups
            ];
            
            foreach ($proxy_headers as $header) {
                if (!empty($_SERVER[$header])) {
                    $ips = array_map('trim', explode(',', $_SERVER[$header]));
                    
                    foreach ($ips as $possible_ip) {
                        // Validate IP
                        if (filter_var($possible_ip, FILTER_VALIDATE_IP)) {
                            $this->log('debug', "IP detected from $header: $possible_ip");
                            $ip = $possible_ip;
                            break 2;
                        }
                    }
                }
            }
        }
        
        // Fall back to REMOTE_ADDR
        if ($ip === '0.0.0.0') {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
            $this->log('debug', "IP from REMOTE_ADDR: $ip");
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
        [$subnet, $bits] = explode('/', $cidr);
        
        // IPv4
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
            filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $mask = -1 << (32 - (int)$bits);
            return (ip2long($ip) & $mask) === (ip2long($subnet) & $mask);
        }
        
        // IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && 
            filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $subnet_bin = inet_pton($subnet);
            $ip_bin = inet_pton($ip);
            
            $bytes_to_check = intdiv((int)$bits, 8);
            $bits_to_check = (int)$bits % 8;
            
            for ($i = 0; $i < $bytes_to_check; $i++) {
                if ($subnet_bin[$i] !== $ip_bin[$i]) {
                    return false;
                }
            }
            
            if ($bits_to_check > 0 && $bytes_to_check < 16) {
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
