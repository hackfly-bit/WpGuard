<?php
/**
 * Test WordPress configuration file
 */

// ** MySQL settings ** //
define('DB_NAME', 'test_db');
define('DB_USER', 'test_user');
define('DB_PASSWORD', 'test_pass');
define('DB_HOST', 'localhost');

// Security keys
define('AUTH_KEY', 'test-auth-key');
define('SECURE_AUTH_KEY', 'test-secure-auth-key');

$table_prefix = 'wp_';

if ( !defined('ABSPATH') )
    define('ABSPATH', dirname(__FILE__) . '/');

require_once(ABSPATH . 'wp-settings.php');
