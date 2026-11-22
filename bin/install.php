#!/usr/bin/env php
<?php
/**
 * Duo Auth Installation Script
 * 
 * This script sets up the Duo Auth plugin for first-time use
 */

echo "=========================================\n";
echo "     Duo Auth Plugin Installation       \n";
echo "=========================================\n\n";

// Check PHP version
echo "Checking PHP version... ";
if (version_compare(PHP_VERSION, '8.0.0', '<')) {
    echo "FAILED\n";
    die("Error: PHP 8.0 or higher is required. You have PHP " . PHP_VERSION . "\n");
}
echo "OK (PHP " . PHP_VERSION . ")\n";

// Check required PHP extensions
echo "Checking required PHP extensions...\n";
$required_extensions = [
    'json' => 'JSON support',
    'curl' => 'cURL for API calls',
    'openssl' => 'OpenSSL for encryption',
    'filter' => 'Filter functions for IP validation',
];

$missing_extensions = [];
foreach ($required_extensions as $ext => $description) {
    echo "  - {$ext} ({$description})... ";
    if (!extension_loaded($ext)) {
        echo "MISSING\n";
        $missing_extensions[] = $ext;
    } else {
        echo "OK\n";
    }
}

if (!empty($missing_extensions)) {
    echo "\nError: The following PHP extensions are required but not installed:\n";
    foreach ($missing_extensions as $ext) {
        echo "  - {$ext}\n";
    }
    echo "\nInstall them using your package manager, for example:\n";
    echo "  Ubuntu/Debian: sudo apt-get install php-{extension}\n";
    echo "  CentOS/RHEL: sudo yum install php-{extension}\n";
    echo "  Docker: Add to Dockerfile: RUN docker-php-ext-install {extension}\n";
    die("\nInstallation aborted.\n");
}

// Check if we're in the right directory
echo "\nChecking installation directory... ";
if (!file_exists('duo_auth.php')) {
    echo "ERROR\n";
    die("Error: duo_auth.php not found. Please run this script from the plugin directory.\n");
}
echo "OK\n";

// Detect web server user (used for config ownership advice)
$web_user = null;
if (function_exists('posix_getpwnam')) {
    foreach (['www-data', 'apache', 'nginx', 'httpd'] as $user) {
        if (posix_getpwnam($user)) {
            $web_user = $user;
            break;
        }
    }
}
$web_group = $web_user ?? '<web-server-group>';

// Copy configuration file if it doesn't exist
echo "\nSetting up configuration...\n";
$config_file = 'config.inc.php';
$config_dist = 'config.inc.php.dist';

if (!file_exists($config_file)) {
    if (file_exists($config_dist)) {
        echo "  - Copying configuration template... ";
        if (copy($config_dist, $config_file)) {
            echo "OK\n";
            // Config holds duo_client_secret: owner read/write, group read, no world access
            chmod($config_file, 0640);
            echo "  - Permissions set to 0640. Make it readable by the web server with:\n";
            echo "      sudo chown root:{$web_group} {$config_file}\n";
            echo "\n";
            echo "╔════════════════════════════════════════════════════════════╗\n";
            echo "║                    IMPORTANT!                              ║\n";
            echo "║                                                            ║\n";
            echo "║  Configuration file created: config.inc.php               ║\n";
            echo "║                                                            ║\n";
            echo "║  You MUST edit this file with your Duo credentials:       ║\n";
            echo "║    - \$config['duo_client_id']                             ║\n";
            echo "║    - \$config['duo_client_secret']                         ║\n";
            echo "║    - \$config['duo_api_hostname']                          ║\n";
            echo "║    - \$config['duo_redirect_uri']                          ║\n";
            echo "║                                                            ║\n";
            echo "║  Get these from: https://admin.duosecurity.com            ║\n";
            echo "╚════════════════════════════════════════════════════════════╝\n";
        } else {
            echo "FAILED\n";
            echo "Warning: Could not create configuration file\n";
            echo "Please manually copy {$config_dist} to {$config_file}\n";
        }
    } else {
        echo "  - Configuration template ({$config_dist}) not found!\n";
        echo "  - Please create {$config_file} manually\n";
    }
} else {
    echo "  - Configuration file already exists... OK\n";

    if (fileperms($config_file) & 0004) {
        echo "  - WARNING: {$config_file} is world-readable and contains duo_client_secret. Run:\n";
        echo "      chmod 0640 {$config_file} && sudo chown root:{$web_group} {$config_file}\n";
    }
    
    // Check configuration validity
    echo "  - Checking configuration... ";
    $config_valid = true;
    $config_errors = [];
    
    // Try to include the config file
    $config = [];
    include $config_file;
    
    // Check required fields
    $required_fields = [
        'duo_client_id' => 'Duo Client ID',
        'duo_client_secret' => 'Duo Client Secret',
        'duo_api_hostname' => 'Duo API Hostname',
        'duo_redirect_uri' => 'Duo Redirect URI'
    ];
    
    foreach ($required_fields as $field => $description) {
        if (!isset($config[$field]) || 
            $config[$field] === 'YOUR_CLIENT_ID_HERE' ||
            $config[$field] === 'YOUR_CLIENT_SECRET_HERE' ||
            $config[$field] === 'api-xxxxxxxx.duosecurity.com' ||
            strpos($config[$field], 'your-domain.com') !== false) {
            $config_valid = false;
            $config_errors[] = $description;
        }
    }
    
    if ($config_valid) {
        echo "OK\n";
    } else {
        echo "INCOMPLETE\n";
        echo "\n";
        echo "╔════════════════════════════════════════════════════════════╗\n";
        echo "║                    WARNING!                                ║\n";
        echo "║                                                            ║\n";
        echo "║  Configuration incomplete! Please update:                  ║\n";
        foreach ($config_errors as $error) {
            printf("║  - %-55s ║\n", $error);
        }
        echo "║                                                            ║\n";
        echo "║  Edit config.inc.php with your actual Duo credentials     ║\n";
        echo "╚════════════════════════════════════════════════════════════╝\n";
    }
}

// Check for old configuration file
if (file_exists('duo_auth.conf')) {
    echo "\n";
    echo "╔════════════════════════════════════════════════════════════╗\n";
    echo "║                    NOTICE                                  ║\n";
    echo "║                                                            ║\n";
    echo "║  Old configuration file (duo_auth.conf) detected!         ║\n";
    echo "║                                                            ║\n";
    echo "║  This plugin now uses config.inc.php instead.             ║\n";
    echo "║  Please migrate your settings and remove duo_auth.conf    ║\n";
    echo "║                                                            ║\n";
    echo "║  Old format → New format:                                 ║\n";
    echo "║    ikey → \$config['duo_client_id']                        ║\n";
    echo "║    skey → \$config['duo_client_secret']                    ║\n";
    echo "║    host → \$config['duo_api_hostname']                     ║\n";
    echo "╚════════════════════════════════════════════════════════════╗\n";
}

// Check Composer dependencies
echo "\nChecking Composer dependencies...\n";
if (file_exists('vendor/autoload.php')) {
    echo "  - Dependencies installed... ";
    
    // Check for Duo SDK specifically
    if (file_exists('vendor/duosecurity/duo_universal_php/src/Client.php')) {
        echo "OK\n";
        
        // Check version
        $composer_lock = json_decode(file_get_contents('composer.lock'), true);
        foreach ($composer_lock['packages'] ?? [] as $package) {
            if ($package['name'] === 'duosecurity/duo_universal_php') {
                echo "  - Duo SDK version: {$package['version']}\n";
                break;
            }
        }
    } else {
        echo "INCOMPLETE\n";
        echo "  - Duo SDK not found. Run: composer install\n";
    }
} else {
    echo "  - Dependencies NOT installed!\n";
    echo "  - Run: composer install\n";
}

// Logging goes through Roundcube's own log driver - nothing to create here
echo "\nLogging: written by Roundcube to its log_dir as duo_auth.log\n";
echo "  (e.g. <roundcube>/logs/duo_auth.log, or syslog/stdout per log_driver)\n\n";

// Check Roundcube integration
echo "\nChecking Roundcube integration...\n";

// Try to find Roundcube config
$rc_config_paths = [
    '../../config/config.inc.php',
    '../../config/main.inc.php',
    '../../config.inc.php'
];

$rc_config_found = false;
foreach ($rc_config_paths as $path) {
    if (file_exists($path)) {
        $rc_config_found = $path;
        break;
    }
}

if ($rc_config_found) {
    echo "  - Roundcube config found at: {$rc_config_found}\n";
    
    // Check if plugin is enabled
    $rc_config_content = file_get_contents($rc_config_found);
    if (strpos($rc_config_content, "'duo_auth'") !== false || 
        strpos($rc_config_content, '"duo_auth"') !== false) {
        echo "  - Plugin appears to be enabled in Roundcube config ✓\n";
    } else {
        echo "  - Plugin NOT enabled in Roundcube config\n";
        echo "  - Add to \$config['plugins'] array:\n";
        echo "      \$config['plugins'] = ['duo_auth', /* other plugins */];\n";
    }
} else {
    echo "  - Roundcube config not found\n";
    echo "  - Make sure to add 'duo_auth' to \$config['plugins'] in Roundcube config\n";
}

// Final summary
echo "\n";
echo "=========================================\n";
echo "       Installation Summary              \n";
echo "=========================================\n\n";

$steps_completed = [];
$steps_remaining = [];

// Check what's done
if (file_exists($config_file)) {
    $steps_completed[] = "✓ Configuration file created";
} else {
    $steps_remaining[] = "Create config.inc.php from config.inc.php.dist";
}

if (file_exists('vendor/autoload.php')) {
    $steps_completed[] = "✓ Composer dependencies installed";
} else {
    $steps_remaining[] = "Run: composer install";
}

// Show completed steps
if (!empty($steps_completed)) {
    echo "Completed:\n";
    foreach ($steps_completed as $step) {
        echo "  {$step}\n";
    }
    echo "\n";
}

// Show remaining steps
if (!empty($steps_remaining)) {
    echo "To Do:\n";
    foreach ($steps_remaining as $step) {
        echo "  1. {$step}\n";
    }
    echo "\n";
}

echo "Next Steps:\n";
echo "1. Edit config.inc.php with your Duo credentials\n";
echo "2. Ensure 'duo_auth' is in \$config['plugins'] in Roundcube config\n";
echo "3. Test with: php -l duo_auth.php\n";
echo "4. Access Roundcube and test authentication\n";
echo "\n";
echo "Documentation: https://github.com/leonardomarino/duo_auth\n";
echo "Support: https://github.com/leonardomarino/duo_auth/issues\n\n";

exit(0);
