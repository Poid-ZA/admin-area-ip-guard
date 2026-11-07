<?php
/**
 * WordPress glue tests with stubbed core functions. Run: php tests/glue.php
 *
 * The deny case calls exit() inside wpag_gate(), so it runs in a child process
 * (`php tests/glue.php deny`) and the parent checks its output.
 */

define('ABSPATH', __DIR__ . '/');

$WPAG_OPTS = array();
$WPAG_ERRORS = array();

function get_option($name, $default = false) { global $WPAG_OPTS; return array_key_exists($name, $WPAG_OPTS) ? $WPAG_OPTS[$name] : $default; }
function update_option($name, $value, $autoload = null) { global $WPAG_OPTS; $WPAG_OPTS[$name] = $value; return true; }
function add_action($hook, $cb, $prio = 10) { return true; }
function register_activation_hook($file, $cb) { return true; }
function add_options_page(...$args) { return true; }
function register_setting(...$args) { return true; }
function add_settings_section(...$args) { return true; }
function add_settings_field(...$args) { return true; }
function add_settings_error($setting, $code, $message) { global $WPAG_ERRORS; $WPAG_ERRORS[] = array($code, $message); }
function settings_errors($setting = '') { return true; }
function __($s, $d = null) { return $s; }
function esc_html($s) { return htmlspecialchars((string) $s, ENT_QUOTES); }
function status_header($code) { $GLOBALS['WPAG_STATUS'] = $code; }
function nocache_headers() { return true; }
// Simplified stand-ins: the real functions also strip slashes and tags.
function wp_unslash($v) { return is_string($v) ? stripslashes($v) : $v; }
function sanitize_text_field($v) { return trim((string) $v); }
function sanitize_key($v) { return strtolower(preg_replace('/[^a-z0-9_\-]/', '', (string) $v)); }

require __DIR__ . '/../admin-area-ip-guard.php';

$failures = 0;
$passes = 0;

function check(string $label, $expected, $actual): void {
	global $failures, $passes;
	if ($expected === $actual) {
		$passes++;
		return;
	}
	$failures++;
	echo "FAIL: {$label}\n  expected: " . var_export($expected, true) . "\n  actual:   " . var_export($actual, true) . "\n";
}

// Deny case, child process. Expect the 403 status line and the body, no later output.
if (isset($argv[1]) && $argv[1] === 'deny') {
	$_SERVER['SCRIPT_FILENAME'] = isset($argv[2]) ? $argv[2] : '/var/www/html/wp-admin/index.php';
	if (isset($argv[3])) {
		$_GET['action'] = $argv[3];
	}
	$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
	$WPAG_OPTS[WPAG_OPTION] = '203.0.113.0/24';
	register_shutdown_function(function () { echo "STATUS:{$GLOBALS['WPAG_STATUS']}\n"; });
	wpag_gate();
	echo "NOT BLOCKED\n";
	exit(0);
}

// Gate, allowed client: returns without output.
$_SERVER['SCRIPT_FILENAME'] = '/var/www/html/wp-admin/index.php';
$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$WPAG_OPTS[WPAG_OPTION] = '203.0.113.0/24';
ob_start();
wpag_gate();
check('gate allows allowlisted ip', '', ob_get_clean());

// Gate, unprotected script from outside the allowlist: passes through.
$_SERVER['SCRIPT_FILENAME'] = '/var/www/html/index.php';
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
ob_start();
wpag_gate();
check('gate ignores unprotected script', '', ob_get_clean());

// Gate, admin-ajax from outside the allowlist: passes through (FR-5).
$_SERVER['SCRIPT_FILENAME'] = '/var/www/html/wp-admin/admin-ajax.php';
ob_start();
wpag_gate();
check('gate exempts admin-ajax', '', ob_get_clean());

// Gate, postpass from outside the allowlist: passes through.
$_SERVER['SCRIPT_FILENAME'] = '/var/www/html/wp-login.php';
$_GET['action'] = 'postpass';
ob_start();
wpag_gate();
check('gate exempts postpass', '', ob_get_clean());
unset($_GET['action']);

// Deny cases run in child processes with the executed script passed as argv[2].
// PATH_INFO on wp-login.php: the executed file is wp-login.php, so it is denied.
$out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' deny ' . escapeshellarg('/var/www/html/wp-login.php') . ' 2>&1');
check('wp-login denied for path info request (child process)', "Forbidden\nSTATUS:403\n", $out);

// postpass only exempts wp-login.php. An admin script with action=postpass stays gated.
$out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' deny ' . escapeshellarg('/var/www/html/wp-admin/options.php') . ' postpass 2>&1');
check('postpass does not unlock admin script (child process)', "Forbidden\nSTATUS:403\n", $out);

// admin-post from outside the allowlist: gated (FR-6).
$out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' deny ' . escapeshellarg('/var/www/html/wp-admin/admin-post.php') . ' 2>&1');
check('admin-post denied (child process)', "Forbidden\nSTATUS:403\n", $out);

// Gate, empty allowlist: fail open (NFR-6).
$_SERVER['SCRIPT_FILENAME'] = '/var/www/html/wp-login.php';
$WPAG_OPTS[WPAG_OPTION] = '';
ob_start();
wpag_gate();
check('gate fails open on empty list', '', ob_get_clean());

// Constant allowlist works with empty option (AC-8, FR-9).
if (!defined('WPAG_ALLOWED_IPS')) {
	define('WPAG_ALLOWED_IPS', array('192.0.2.0/24', 42, 'junk'));
}
$_SERVER['REMOTE_ADDR'] = '192.0.2.5';
check('constant rules only valid strings', array('192.0.2.0/24'), wpag_constant_rules());
ob_start();
wpag_gate();
check('constant rule admits client with empty option', '', ob_get_clean());

// Sanitize: lockout refused, previous value kept (AC-7).
$WPAG_ERRORS = array();
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
$WPAG_OPTS[WPAG_OPTION] = '198.51.100.7';
$result = wpag_sanitize("203.0.113.0/24");
check('sanitize keeps previous on lockout', '198.51.100.7', $result);
check('sanitize reports lockout', 'wpag_lockout', $WPAG_ERRORS[0][0] ?? null);

// Sanitize: list including current IP saves normalized text.
$WPAG_ERRORS = array();
$result = wpag_sanitize("203.0.113.0/24,198.51.100.7\n bogus/99");
check('sanitize saves valid list', "203.0.113.0/24\n198.51.100.7", $result);
check('sanitize reports invalid entry', 'wpag_invalid', $WPAG_ERRORS[0][0] ?? null);

// Sanitize: clearing the list while outside is refused (a clear would fail open).
$WPAG_ERRORS = array();
$WPAG_OPTS[WPAG_OPTION] = '203.0.113.0/24';
$result = wpag_sanitize('');
check('sanitize refuses clear from outside', '203.0.113.0/24', $result);

// Sanitize: non-string input is treated as empty. Constant rule admits 192.0.2.5,
// so the clear is allowed and the result is an empty string.
$WPAG_ERRORS = array();
$_SERVER['REMOTE_ADDR'] = '192.0.2.5';
$result = wpag_sanitize(array('x'));
check('sanitize non-string input clears when constant admits ip', '', $result);

// Activation seeds the allowlist with the current IP when empty.
$WPAG_OPTS = array();
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
wpag_activate();
check('activation seeds current ip', '198.51.100.7', get_option(WPAG_OPTION));

// Activation does not overwrite an existing list.
$WPAG_OPTS[WPAG_OPTION] = '203.0.113.0/24';
wpag_activate();
check('activation keeps existing list', '203.0.113.0/24', get_option(WPAG_OPTION));

// Deny path in a child process.
$out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' deny 2>&1');
check('gate denies outside client', "Forbidden\nSTATUS:403\n", $out);

if ($failures > 0) {
	echo "\n{$failures} failed, {$passes} passed\n";
	exit(1);
}
echo "{$passes} passed\n";
exit(0);
