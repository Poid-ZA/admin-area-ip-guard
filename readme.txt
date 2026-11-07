=== Admin Area IP Guard ===
Contributors: wehnkebotha
Tags: security, wp-admin, login, ip, access
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restricts /wp-admin/ and wp-login.php to an IP allowlist.

== Description ==

Requests to /wp-admin/ and wp-login.php are denied with HTTP 403 unless the
client address is on the allowlist. The allowlist accepts single IPv4 or IPv6
addresses and CIDR ranges, one per line.

Not gated:

* /wp-admin/admin-ajax.php. Public pages use it, and its own permission checks still apply.
* wp-login.php?action=postpass. Password-protected posts use it to unlock content. It only sets a cookie and redirects.
* Everything outside wp-admin and wp-login.php, including the front end and the REST API.
* xmlrpc.php. Out of scope for version 1.0.

The settings page refuses to save a list that excludes your current address,
so you cannot lock yourself out from the browser.

== Installation ==

1. Copy the admin-area-ip-guard folder to wp-content/plugins/.
2. Activate the plugin. Your current address is added to the allowlist if the list is empty.
3. Open Settings > Admin Area IP Guard and add the networks you need.

== Behavior notes ==

* An empty allowlist does not restrict anything. The settings page shows a warning in this state.
* The gate decides by the script the server runs (SCRIPT_FILENAME), not by the URL. The server must set SCRIPT_FILENAME or SCRIPT_NAME. Standard Apache and nginx + php-fpm setups do.
* Only REMOTE_ADDR is used to identify the client. X-Forwarded-For is ignored because clients can set it.
  If the site sits behind a reverse proxy or CDN, REMOTE_ADDR is the proxy's address, not the visitor's.
  Confirm the address the server sees before enabling enforcement.

== Recovery ==

Add these to wp-config.php, above the "stop editing" line:

* define('WPAG_ALLOWED_IPS', array('203.0.113.0/24')); always allows these addresses, even when the database list is empty. The settings page cannot remove them.
* define('WPAG_DISABLED', true); turns enforcement off without deactivating the plugin. Remove it to turn enforcement back on.

Clearing the stored list with WP-CLI (wp option delete wpag_allowed) also turns enforcement off, because an empty list fails open.

Deleting the plugin removes the wpag_allowed option.

== Changelog ==

= 1.0.0 =
* Initial release: IP and CIDR allowlist for wp-admin and wp-login.php, lockout-safe settings page, activation seeding, wp-config overrides.
