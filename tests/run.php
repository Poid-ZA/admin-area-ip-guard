<?php
/**
 * Unit tests for includes/rules.php. Run: php tests/run.php
 * Exits nonzero on any failure.
 */

define('ABSPATH', __DIR__ . '/');
require __DIR__ . '/../includes/rules.php';

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

// FR-1, FR-6: scripts the server executes that must be gated.
$protectedScripts = array(
	'/var/www/html/wp-admin/index.php',
	'/var/www/html/wp-admin/options.php',
	'/var/www/html/wp-admin/admin-post.php',            // FR-6
	'/var/www/html/wp-admin/load-styles.php',
	'/var/www/html/WP-ADMIN/Index.PHP',                 // case-insensitive FS or mixed case
	'C:\\inetpub\\wwwroot\\wp-admin\\index.php',        // Windows separators
	'/var/www/html/blog/wp-admin/index.php',            // subdirectory install
	'/var/www/html/wp-login.php',
	'/var/www/html/blog/wp-login.php',
	'/var/www/html/WP-Login.PHP',
);
foreach ($protectedScripts as $file) {
	check("protected script: {$file}", true, wpag_is_protected_script($file));
}

// FR-5: admin-ajax.php is exempt.
check('admin-ajax exempt', false, wpag_is_protected_script('/var/www/html/wp-admin/admin-ajax.php'));
check('admin-ajax exempt in subdir', false, wpag_is_protected_script('/var/www/html/blog/wp-admin/admin-ajax.php'));

// Not protected.
foreach (array(
	'/var/www/html/index.php',
	'/var/www/html/wp-includes/load.php',
	'/var/www/html/wp-admin.php',                       // file named like the dir, not in it
	'/var/www/html/wp-admin-tools/index.php',
) as $file) {
	check("unprotected script: {$file}", false, wpag_is_protected_script($file));
}
// PATH_INFO: /index.php/wp-admin/options.php executes index.php, which is not gated.
check('index.php executed for wp-admin path info', false, wpag_is_protected_script('/var/www/html/index.php'));
// PATH_INFO: /wp-login.php/x executes wp-login.php, which is gated.
check('wp-login.php executed with path info', true, wpag_is_protected_script('/var/www/html/wp-login.php'));
// Login detection for the postpass exemption.
check('login script detected', true, wpag_is_login_script('/var/www/html/wp-login.php'));
check('admin script is not login', false, wpag_is_login_script('/var/www/html/wp-admin/options.php'));

// FR-4: CIDR and address matching, IPv4.
check('v4 in /24', true, wpag_ip_in_cidr('203.0.113.9', '203.0.113.0/24'));          // AC-2
check('v4 outside /24', false, wpag_ip_in_cidr('198.51.100.7', '203.0.113.0/24'));    // AC-1
check('v4 exact', true, wpag_ip_in_cidr('203.0.113.9', '203.0.113.9'));
check('v4 exact miss', false, wpag_ip_in_cidr('203.0.113.10', '203.0.113.9'));
check('v4 /25 boundary in', true, wpag_ip_in_cidr('10.0.0.127', '10.0.0.0/25'));
check('v4 /25 boundary out', false, wpag_ip_in_cidr('10.0.0.128', '10.0.0.0/25'));
check('v4 /0 matches all', true, wpag_ip_in_cidr('8.8.8.8', '0.0.0.0/0'));
check('v4 /32', true, wpag_ip_in_cidr('1.2.3.4', '1.2.3.4/32'));

// IPv6.
check('v6 /32 in', true, wpag_ip_in_cidr('2001:db8::1', '2001:db8::/32'));
check('v6 /32 out', false, wpag_ip_in_cidr('2001:db9::1', '2001:db8::/32'));
check('v6 /64 boundary', false, wpag_ip_in_cidr('2001:db8:0:1::1', '2001:db8::/64'));
check('v6 exact', true, wpag_ip_in_cidr('2001:db8::1', '2001:db8::1/128'));

// AC-6: IPv4-mapped IPv6 client against IPv4 rule, and the reverse.
check('mapped client vs v4 rule', true, wpag_ip_in_cidr('::ffff:203.0.113.9', '203.0.113.0/24'));
check('mapped client outside v4 rule', false, wpag_ip_in_cidr('::ffff:198.51.100.7', '203.0.113.0/24'));
check('v4 client vs mapped rule', true, wpag_ip_in_cidr('203.0.113.9', '::ffff:203.0.113.0/120'));
check('mapped rule /96 covers all v4', true, wpag_ip_in_cidr('1.2.3.4', '::ffff:0:0/96'));
check('mapped rule prefix below 96 rejected', false, wpag_ip_in_cidr('1.2.3.4', '::/80'));

// Family mismatch never matches.
check('v6 client vs v4 rule', false, wpag_ip_in_cidr('2001:db8::1', '0.0.0.0/0'));
check('v4 client vs v6 rule', false, wpag_ip_in_cidr('1.2.3.4', '2001:db8::/32'));

// Garbage input.
check('empty ip', false, wpag_ip_in_cidr('', '10.0.0.0/8'));
check('garbage ip', false, wpag_ip_in_cidr('not-an-ip', '10.0.0.0/8'));
check('garbage rule', false, wpag_ip_in_cidr('10.0.0.1', 'junk/8'));
check('prefix too large v4', false, wpag_ip_in_cidr('10.0.0.1', '10.0.0.0/33'));
check('prefix too large v6', false, wpag_ip_in_cidr('2001:db8::1', '2001:db8::/129'));
check('prefix non-numeric', false, wpag_ip_in_cidr('10.0.0.1', '10.0.0.0/x'));
check('prefix negative', false, wpag_ip_in_cidr('10.0.0.1', '10.0.0.0/-1'));

// Parsing.
$parsed = wpag_parse_rules("203.0.113.0/24\n  2001:db8::/32, 198.51.100.7 \n\n10.0.0.0/33\nbogus\n");
check('parse valid', array('203.0.113.0/24', '2001:db8::/32', '198.51.100.7'), $parsed['valid']);
check('parse invalid', array('10.0.0.0/33', 'bogus'), $parsed['invalid']);
check('parse empty', array('valid' => array(), 'invalid' => array()), wpag_parse_rules(''));

// wpag_ip_allowed.
check('allowed match', true, wpag_ip_allowed('203.0.113.9', array('198.51.100.0/24', '203.0.113.0/24')));
check('allowed no match', false, wpag_ip_allowed('192.0.2.1', array('198.51.100.0/24')));
check('allowed empty list', false, wpag_ip_allowed('203.0.113.9', array()));  // AC-5 basis

if ($failures > 0) {
	echo "\n{$failures} failed, {$passes} passed\n";
	exit(1);
}
echo "{$passes} passed\n";
exit(0);
