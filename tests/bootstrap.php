<?php
/**
 * PHPUnit Bootstrap for Duo Auth Plugin Tests
 * 
 * Provides mock classes for Roundcube framework components
 */

require_once __DIR__ . '/../vendor/autoload.php';

// 1. Mock the parent 'rcube_plugin' class if Roundcube isn't actually loaded
if (!class_exists('rcube_plugin')) {
    class rcube_plugin {
        public $task;
        protected $api;
        public function __construct($api) { $this->api = $api; }
        public function load_config($fname = 'config.inc.php') {}
        public function add_hook($hook, $callback) {}
        public function register_action($action, $callback) {}
        public function register_handler($handler, $callback) {}
        public function include_script($path) {}
    }
}

// 2. Mock the main 'rcube' singleton
if (!class_exists('rcube')) {
    class rcube {
        public static $instance;
        public $config;
        public $session;
        public $output;
        public $user;
        public $task = '';
        public $action = '';
        
        // Track method calls for testing
        public $killed_session = false;
        
        public static function get_instance() {
            if (!self::$instance) {
                self::$instance = new self();
                self::$instance->config = new rcube_config();
                self::$instance->session = new rcube_session();
                self::$instance->output = new rcube_output();
                self::$instance->user = null;
            }
            return self::$instance;
        }
        
        /**
         * Reset the singleton for fresh tests
         */
        public static function reset_instance() {
            self::$instance = null;
        }
        
        /**
         * Kill the current session
         */
        public function kill_session() {
            $this->killed_session = true;
            $_SESSION = [];
        }
        
        /**
         * Write to log (no-op in tests)
         */
        public static function write_log($name, $message) {
            // Optionally collect logs for test verification
            if (!isset($GLOBALS['test_logs'])) {
                $GLOBALS['test_logs'] = [];
            }
            $GLOBALS['test_logs'][] = ['name' => $name, 'message' => $message];
        }
    }
    
    // Helper mock: Configuration
    class rcube_config {
        private $values = [];
        
        public function set($key, $value) {
            $this->values[$key] = $value;
        }
        
        public function get($key, $def = null) {
            return $this->values[$key] ?? $def;
        }
        
        /**
         * Bulk set config values for testing
         */
        public function set_values(array $values) {
            $this->values = array_merge($this->values, $values);
        }
    }
    
    // Helper mock: Session
    class rcube_session {
        public function bind($key, $val) {}
        public function get_unbanned($key) { return null; }
        public function remove($key) {}
        public function kill() {}
    }
    
    // Helper mock: Output
    class rcube_output {
        public $redirected_to = null;
        public $messages = [];
        
        public function redirect($url) {
            $this->redirected_to = $url;
            // Throw exception to simulate exit() behavior in tests
            throw new DuoAuthTestRedirectException($url);
        }
        
        public function show_message($msg, $type = 'info') {
            $this->messages[] = ['message' => $msg, 'type' => $type];
        }
        
        /**
         * Reset for fresh tests
         */
        public function reset() {
            $this->redirected_to = null;
            $this->messages = [];
        }
    }
    
    // Helper mock: Utilities
    class rcube_utils {
        const INPUT_GET = 1;
        const INPUT_POST = 2;
        
        private static $input_values = [];
        
        public static function get_input_value($key, $type) {
            return self::$input_values[$key] ?? null;
        }
        
        public static function set_input_value($key, $value) {
            self::$input_values[$key] = $value;
        }
        
        public static function clear_input_values() {
            self::$input_values = [];
        }
        
        public static function remote_addr() {
            return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        }
        
        public static function check_ip($ip, $arr) {
            return in_array($ip, $arr, true);
        }
    }
    
    // Helper mock: User
    class rcube_user {
        public $ID = null;
        private $username = null;
        
        public function __construct($id = null, $username = null) {
            $this->ID = $id;
            $this->username = $username;
        }
        
        public function get_username() {
            return $this->username;
        }
        
        public function set_username($username) {
            $this->username = $username;
        }
    }
}

/**
 * Custom exception for testing redirects (simulates exit())
 */
class DuoAuthTestRedirectException extends Exception {
    public $url;
    
    public function __construct($url) {
        $this->url = $url;
        parent::__construct("Redirect to: " . (is_array($url) ? json_encode($url) : $url));
    }
}

/**
 * Test helper class for Duo Auth tests
 */
class DuoAuthTestHelper {
    /**
     * Reset all mocks to fresh state
     */
    public static function reset() {
        rcube::reset_instance();
        rcube_utils::clear_input_values();
        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $GLOBALS['test_logs'] = [];
    }
    
    /**
     * Configure the mock rcube instance for testing
     */
    public static function configure(array $options = []): rcube {
        self::reset();
        
        $rc = rcube::get_instance();
        
        // Set task and action
        $rc->task = $options['task'] ?? '';
        $rc->action = $options['action'] ?? '';
        
        // Set user if provided
        if (isset($options['user'])) {
            $rc->user = new rcube_user(
                $options['user']['id'] ?? 1,
                $options['user']['username'] ?? 'testuser'
            );
        }
        
        // Set config values
        $defaultConfig = [
            'duo_enabled' => true,
            'duo_client_id' => 'test_client_id',
            'duo_client_secret' => 'test_secret',
            'duo_api_hostname' => 'api-test.duosecurity.com',
            'duo_redirect_uri' => 'https://example.com/?_task=login&_action=plugin.duo_callback',
            'duo_bypass_users' => [],
            'duo_bypass_ips' => [],
            'duo_bypass_rules' => [],
            'duo_log_enabled' => false,
            'duo_log_level' => 'error',
            'duo_failmode' => 'secure',
            'duo_session_timeout' => 900,
            'duo_timeout' => 300,
        ];
        
        $configValues = array_merge($defaultConfig, $options['config'] ?? []);
        $rc->config->set_values($configValues);
        
        // Set session data
        if (isset($options['session'])) {
            foreach ($options['session'] as $key => $value) {
                $_SESSION[$key] = $value;
            }
        }
        
        // Set server variables
        if (isset($options['remote_addr'])) {
            $_SERVER['REMOTE_ADDR'] = $options['remote_addr'];
        }
        
        return $rc;
    }
    
    /**
     * Get collected test logs
     */
    public static function getLogs(): array {
        return $GLOBALS['test_logs'] ?? [];
    }
}

// 3. Finally, load your plugin file
require_once __DIR__ . '/../duo_auth.php';
