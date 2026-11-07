# WordPress.org submission draft: Admin Area IP Guard 1.0.0

Draft only. Nothing here has been submitted.

## Plugin upload form

- **Plugin ZIP:** `/opt/wp-admin-guard/dist/admin-area-ip-guard.zip`
- **Plugin name:** Admin Area IP Guard
- **Slug requested:** admin-area-ip-guard
- **Short description:** Restricts /wp-admin/ and wp-login.php to an IP allowlist. (matches readme.txt)
- **License:** GPLv2 or later

## Note to the reviewer

Admin Area IP Guard denies requests to wp-admin/*.php and wp-login.php from IP addresses that are not on an allowlist set by the site administrator. It makes no outbound requests, stores one option (`wpag_allowed`), and loads no remote code or assets. Source is plain PHP in `admin-area-ip-guard.php` and `includes/rules.php`. Unit tests are in `tests/`.

How to test:

1. Install and activate on a WordPress 7.1 site.
2. Settings > Admin Area IP Guard shows the activating admin's IP in the allowlist.
3. From a different network (for example a phone on mobile data), request `/wp-admin/` and `/wp-login.php`. Expect HTTP 403 with body "Forbidden".
4. Public pages and `wp-admin/admin-ajax.php` still respond from the other network.
5. The settings page refuses to save a list that excludes the current IP.

Recovery for testers is in readme.txt under "Recovery" (wp-config constants `WPAG_DISABLED` and `WPAG_ALLOWED_IPS`).

## Screenshots to capture (not yet taken)

Capture these at 1280px wide, then add them to readme.txt under a `== Screenshots ==` section and to the `assets/` folder in SVN.

1. Settings > Admin Area IP Guard with an allowlist and "Your current address" visible.
2. Settings page showing the "Not saved" lockout error.
3. Browser showing the "Forbidden" page for `/wp-login.php` from a blocked IP.

## Before submitting

- Confirm `Contributors: wehnkebotha` is the WordPress.org account that owns the submission.
- Confirm the slug `admin-area-ip-guard` is free on WordPress.org.
- Confirm "Tested up to: 7.1" matches the test run.
- Decide whether to add the screenshots before submission or in a later release. Neither affects approval.
