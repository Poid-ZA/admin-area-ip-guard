<?php
/**
 * Runs when the plugin is deleted from wp-admin.
 *
 * @package AdminAreaIPGuard
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
	exit;
}

delete_option('wpag_allowed');
