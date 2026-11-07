<?php
/**
 * Plugin Name: Admin Area IP Guard
 * Description: Restricts /wp-admin/ and wp-login.php to an IP allowlist.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: admin-area-ip-guard
 *
 * Optional wp-config.php constants:
 *   define('WPAG_ALLOWED_IPS', array('203.0.113.0/24'));  // cannot be removed from the UI
 *   define('WPAG_DISABLED', true);                        // turn enforcement off
 */

if (!defined('ABSPATH')) {
	exit;
}

require_once __DIR__ . '/includes/rules.php';

const WPAG_OPTION = 'wpag_allowed';

/**
 * Allowlist entries from wp-config.php. Invalid or non-string entries are skipped.
 *
 * @return string[]
 */
function wpag_constant_rules(): array {
	if (!defined('WPAG_ALLOWED_IPS') || !is_array(WPAG_ALLOWED_IPS)) {
		return array();
	}
	$rules = array();
	foreach (WPAG_ALLOWED_IPS as $entry) {
		if (is_string($entry) && wpag_is_valid_rule($entry)) {
			$rules[] = $entry;
		}
	}
	return $rules;
}

/**
 * Allowlist entries saved in the database option.
 *
 * @return string[]
 */
function wpag_option_rules(): array {
	$text = get_option(WPAG_OPTION, '');
	if (!is_string($text)) {
		return array();
	}
	return wpag_parse_rules($text)['valid'];
}

/**
 * @return string[]
 */
function wpag_all_rules(): array {
	return array_merge(wpag_constant_rules(), wpag_option_rules());
}

/**
 * Server variable as a clean string. Empty when unset.
 */
function wpag_server_var(string $key): string {
	if (!isset($_SERVER[$key])) {
		return '';
	}
	return sanitize_text_field(wp_unslash((string) $_SERVER[$key]));
}

function wpag_current_ip(): string {
	return wpag_server_var('REMOTE_ADDR');
}

/**
 * Deny protected requests from addresses outside the allowlist.
 *
 * Runs on init, before wp-login.php or wp-admin screens do any work.
 */
function wpag_gate(): void {
	if (defined('WPAG_DISABLED') && WPAG_DISABLED) {
		return;
	}

	// The executed file, not the URI. Falls back to SCRIPT_NAME when the server
	// does not set SCRIPT_FILENAME.
	$script = wpag_server_var('SCRIPT_FILENAME');
	if ($script === '') {
		$script = wpag_server_var('SCRIPT_NAME');
	}
	if (!wpag_is_protected_script($script)) {
		return;
	}

	// Password-protected posts submit to wp-login.php?action=postpass. That
	// branch only sets the post-password cookie and redirects, so exempt it.
	// Read-only routing check, no state change, so no nonce applies.
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$action = isset($_GET['action']) && is_string($_GET['action']) ? sanitize_key($_GET['action']) : '';
	if (wpag_is_login_script($script) && $action === 'postpass') {
		return;
	}

	$rules = wpag_all_rules();
	if (empty($rules)) {
		// Fail open: an empty allowlist must not lock everyone out.
		return;
	}

	if (wpag_ip_allowed(wpag_current_ip(), $rules)) {
		return;
	}

	status_header(403);
	nocache_headers();
	header('Content-Type: text/plain; charset=utf-8');
	echo "Forbidden\n";
	exit;
}
add_action('init', 'wpag_gate', 0);

/**
 * Seed the allowlist with the activating administrator's address so
 * activation cannot lock them out.
 */
function wpag_activate(): void {
	if (!empty(wpag_option_rules())) {
		return;
	}
	$ip = wpag_current_ip();
	if ($ip !== '' && wpag_is_valid_rule($ip)) {
		update_option(WPAG_OPTION, $ip, false);
	}
}
register_activation_hook(__FILE__, 'wpag_activate');

function wpag_admin_menu(): void {
	add_options_page(
		__('Admin Area IP Guard', 'admin-area-ip-guard'),
		__('Admin Area IP Guard', 'admin-area-ip-guard'),
		'manage_options',
		'admin-area-ip-guard',
		'wpag_render_page'
	);
}
add_action('admin_menu', 'wpag_admin_menu');

function wpag_register_settings(): void {
	register_setting(
		'wpag_settings',
		WPAG_OPTION,
		array(
			'type'              => 'string',
			'default'           => '',
			'sanitize_callback' => 'wpag_sanitize',
		)
	);
	add_settings_section('wpag_main', '', '', 'admin-area-ip-guard');
	add_settings_field('wpag_allowed', __('Allowed IPs', 'admin-area-ip-guard'), 'wpag_render_field', 'admin-area-ip-guard', 'wpag_main');
}
add_action('admin_init', 'wpag_register_settings');

/**
 * Validate the submitted list. Refuses any save that would lock out the
 * administrator making the change.
 */
function wpag_sanitize($input): string {
	$previous = get_option(WPAG_OPTION, '');
	$parsed = wpag_parse_rules(is_string($input) ? $input : '');

	foreach ($parsed['invalid'] as $entry) {
		add_settings_error(
			WPAG_OPTION,
			'wpag_invalid',
			/* translators: %s: rejected allowlist entry */
			sprintf(__('Ignored invalid entry: %s', 'admin-area-ip-guard'), esc_html($entry))
		);
	}

	$effective = array_merge(wpag_constant_rules(), $parsed['valid']);
	if (!wpag_ip_allowed(wpag_current_ip(), $effective)) {
		add_settings_error(
			WPAG_OPTION,
			'wpag_lockout',
			sprintf(
				/* translators: %s: current IP address */
				__('Not saved: the list must include your current address (%s), or you would be locked out.', 'admin-area-ip-guard'),
				esc_html(wpag_current_ip())
			)
		);
		return is_string($previous) ? $previous : '';
	}

	return implode("\n", $parsed['valid']);
}

function wpag_render_field(): void {
	$constant = wpag_constant_rules();
	?>
	<textarea name="<?php echo esc_attr(WPAG_OPTION); ?>" rows="6" cols="50" class="large-text code"><?php echo esc_textarea((string) get_option(WPAG_OPTION, '')); ?></textarea>
	<p class="description">
		<?php esc_html_e('One IP address or CIDR range per line (for example 203.0.113.0/24 or 2001:db8::/32).', 'admin-area-ip-guard'); ?>
	</p>
	<p class="description">
		<?php
		/* translators: %s: current IP address */
		echo esc_html(sprintf(__('Your current address: %s', 'admin-area-ip-guard'), wpag_current_ip()));
		?>
	</p>
	<?php if (!empty($constant)) : ?>
		<p class="description">
			<?php
			/* translators: %s: comma-separated allowlist entries */
			echo esc_html(sprintf(__('Always allowed (set in wp-config.php): %s', 'admin-area-ip-guard'), implode(', ', $constant)));
			?>
		</p>
	<?php endif; ?>
	<?php if (empty(wpag_all_rules())) : ?>
		<p><strong><?php esc_html_e('The allowlist is empty, so wp-admin and wp-login.php are not restricted.', 'admin-area-ip-guard'); ?></strong></p>
	<?php endif; ?>
	<?php
}

function wpag_render_page(): void {
	if (!current_user_can('manage_options')) {
		wp_die(esc_html__('You do not have permission to access this page.', 'admin-area-ip-guard'), 403);
	}
	?>
	<div class="wrap">
		<h1><?php esc_html_e('Admin Area IP Guard', 'admin-area-ip-guard'); ?></h1>
		<?php settings_errors(WPAG_OPTION); ?>
		<form method="post" action="options.php">
			<?php
			settings_fields('wpag_settings');
			do_settings_sections('admin-area-ip-guard');
			submit_button();
			?>
		</form>
	</div>
	<?php
}
