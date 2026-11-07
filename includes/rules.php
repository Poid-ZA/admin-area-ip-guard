<?php
/**
 * Pure matching logic for Admin Area IP Guard. No WordPress calls live here so the
 * test suite can load this file on its own.
 *
 * @package AdminAreaIPGuard
 */

if ( ! defined( 'ABSPATH' ) ) exit;

const WPAG_MAPPED_V4_PREFIX = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

/**
 * Lowercase basename and parent directory name of the executed script file.
 *
 * The gate keys on the file the server runs (SCRIPT_FILENAME), not on the
 * request URI. The URI can carry PATH_INFO or encodings that the server
 * resolves differently; the executed file cannot.
 *
 * @return array{0: string, 1: string} [basename, parent directory name]
 */
function wpag_script_parts(string $file): array {
	$file = strtolower(str_replace('\\', '/', $file));
	return array(basename($file), basename(dirname($file)));
}

/**
 * True for wp-login.php and for any script directly inside a wp-admin
 * directory, except admin-ajax.php (the frontend depends on it; its own auth
 * checks still apply).
 */
function wpag_is_protected_script(string $file): bool {
	list($base, $dir) = wpag_script_parts($file);
	if ($base === 'wp-login.php') {
		return true;
	}
	return $dir === 'wp-admin' && $base !== 'admin-ajax.php';
}

function wpag_is_login_script(string $file): bool {
	return wpag_script_parts($file)[0] === 'wp-login.php';
}

/**
 * Split a packed address into bytes and prefix length. IPv4-mapped IPv6
 * addresses become plain IPv4 so ::ffff:1.2.3.4 matches a 1.2.3.4 rule.
 *
 * @return array{0: string, 1: int}|null Null when the prefix cannot be mapped.
 */
function wpag_unmap(string $bin, int $prefix): ?array {
	if (strlen($bin) === 16 && substr($bin, 0, 12) === WPAG_MAPPED_V4_PREFIX) {
		if ($prefix < 96) {
			return null;
		}
		return array(substr($bin, 12), $prefix - 96);
	}
	return array($bin, $prefix);
}

/**
 * True when $ip falls inside $cidr. $cidr may be a bare address (full-length
 * match) or address/prefix. Mixed address families never match.
 */
function wpag_ip_in_cidr(string $ip, string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	$net = @inet_pton($parts[0]);
	$addr = @inet_pton($ip);
	if ($net === false || $addr === false) {
		return false;
	}

	$bits = strlen($net) * 8;
	$prefix = $bits;
	if (isset($parts[1])) {
		if (preg_match('/^\d{1,3}$/', $parts[1]) !== 1) {
			return false;
		}
		$prefix = (int) $parts[1];
	}
	if ($prefix > $bits) {
		return false;
	}

	$netMapped = wpag_unmap($net, $prefix);
	$addrMapped = wpag_unmap($addr, strlen($addr) * 8);
	if ($netMapped === null || $addrMapped === null) {
		return false;
	}
	list($netBin, $netPrefix) = $netMapped;
	$addrBin = $addrMapped[0];
	if (strlen($netBin) !== strlen($addrBin)) {
		return false;
	}

	$fullBytes = intdiv($netPrefix, 8);
	$remBits = $netPrefix % 8;
	if (substr($netBin, 0, $fullBytes) !== substr($addrBin, 0, $fullBytes)) {
		return false;
	}
	if ($remBits === 0) {
		return true;
	}

	$mask = (0xff << (8 - $remBits)) & 0xff;
	return (ord($netBin[$fullBytes]) & $mask) === (ord($addrBin[$fullBytes]) & $mask);
}

/**
 * True when one allowlist entry is a valid address or CIDR.
 */
function wpag_is_valid_rule(string $entry): bool {
	$parts = explode('/', $entry, 2);
	$bin = @inet_pton($parts[0]);
	if ($bin === false) {
		return false;
	}
	if (!isset($parts[1])) {
		return true;
	}
	return preg_match('/^\d{1,3}$/', $parts[1]) === 1 && (int) $parts[1] <= strlen($bin) * 8;
}

/**
 * Split allowlist text on whitespace and commas into valid and invalid entries.
 *
 * @return array{valid: string[], invalid: string[]}
 */
function wpag_parse_rules(string $text): array {
	$valid = array();
	$invalid = array();
	$entries = preg_split('/[\s,]+/', $text, -1, PREG_SPLIT_NO_EMPTY);
	if ($entries === false) {
		return array('valid' => $valid, 'invalid' => $invalid);
	}
	foreach ($entries as $entry) {
		if (wpag_is_valid_rule($entry)) {
			$valid[] = $entry;
		} else {
			$invalid[] = $entry;
		}
	}
	return array('valid' => $valid, 'invalid' => $invalid);
}

/**
 * True when $ip matches any rule. An empty rule list matches nothing.
 *
 * @param string[] $rules
 */
function wpag_ip_allowed(string $ip, array $rules): bool {
	foreach ($rules as $rule) {
		if (wpag_ip_in_cidr($ip, $rule)) {
			return true;
		}
	}
	return false;
}
