<?php

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
        
        public static function get_instance() {
            if (!self::$instance) {
                self::$instance = new self();
                self::$instance->config = new rcube_config();
                self::$instance->session = new rcube_session();
                self::$instance->output = new rcube_output();
            }
            return self::$instance;
        }
    }
    
    // Helper mocks
    class rcube_config {
        public function get($key, $def = null) { return $def; }
    }
    class rcube_session {
        public function bind($key, $val) {}
        public function get_unbanned($key) { return null; }
        public function remove($key) {}
        public function kill() {}
    }
    class rcube_output {
        public function redirect($url) {}
        public function show_message($msg, $type='info') {}
    }
    class rcube_utils {
        const INPUT_GET = 1;
        const INPUT_POST = 2;
        public static function get_input_value($key, $type) { return null; }
        public static function remote_addr() { return '127.0.0.1'; }
        public static function check_ip($ip, $arr) { return false; }
    }
}

// 3. Finally, load your plugin file
require_once __DIR__ . '/../duo_auth.php';
