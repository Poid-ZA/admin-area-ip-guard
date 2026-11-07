# intent.md: WP Admin Guard

## Problem statement

WordPress admin screens (`/wp-admin/`) and the login form (`wp-login.php`) are reachable from any IP address. Credential stuffing and unpatched admin exploits target them directly. The site owner wants admin access limited to known networks.

## Objective

Ship a WordPress plugin that denies HTTP requests to `/wp-admin/` (except the frontend AJAX endpoint) and `wp-login.php` unless the client IP is on an administrator-defined allowlist. The plugin provides a settings page to manage the allowlist and cannot be used to lock the administrator out of the site.

## Functional requirements

Confirmed (from the request):

- FR-1 Gate `/wp-admin/` and `wp-login.php` by client IP against an allowlist.
- FR-2 Provide a settings page to manage the allowlist.
- FR-3 Lockout safety: the plugin must not let the administrator save or activate a configuration that blocks their own current IP.

Proposed (assumptions, to confirm):

- FR-4 Allowlist entries accept single IPv4/IPv6 addresses and CIDR ranges.
- FR-5 `/wp-admin/admin-ajax.php` is exempt from the gate. The frontend uses it, and blocking it breaks public pages. Its own auth checks still apply.
- FR-6 `/wp-admin/admin-post.php` is gated like the rest of wp-admin.
- FR-7 Denied requests get HTTP 403 with a short plain-text body and no detail about the allowlist.
- FR-8 On activation, the activating administrator's current IP is added to the allowlist if the list is empty.
- FR-9 `wp-config.php` constants provide an allowlist that the settings page cannot remove. This is the recovery path if the database option is lost.
- FR-10 `define('WPAG_DISABLED', true)` in `wp-config.php` turns enforcement off without deactivating the plugin.

## Non-functional requirements

- NFR-1 Security: client IP comes from `REMOTE_ADDR` only. `X-Forwarded-For` is not trusted by default because clients can spoof it.
- NFR-2 Security: the gate keys on the script the server executes (`SCRIPT_FILENAME`), not on the request URI. URI parsing can disagree with the server's routing (PATH_INFO, encodings, dot segments), so the gate does not parse the URI at all. Falls back to `SCRIPT_NAME` when `SCRIPT_FILENAME` is unset. Requires that the server sets one of them (checklist item).
- NFR-3 Security: the settings page requires `manage_options` and a valid Settings API nonce.
- NFR-4 Compatibility: WordPress 6.0+, PHP 7.4+. Works in subdirectory installs (`/blog/wp-admin/`).
- NFR-5 Performance: the gate adds no database queries on requests that are not protected paths. Protected requests read one option and the constants.
- NFR-6 Fail-open on empty allowlist. Blocking everything with an empty list would lock out the site with no in-app recovery. The settings page shows a warning in this state.
- NFR-7 No external services, no network calls, no telemetry.

## Constraints

- Single plugin, no Composer dependencies, no build step.
- No PHP extensions beyond core (`inet_pton` is core).
- Test environment: PHP 8.5 CLI only. A full WordPress install is not available on this host, so WP-integrated behavior is verified by a manual checklist (see plan.md), not automated tests.

## Assumptions

- A1 The site runs behind no reverse proxy that rewrites `REMOTE_ADDR`. If it does, the allowlist must match the proxy's address. This must be checked by the owner before enabling. (Open question Q1.)
- A2 Multisite is not in scope. The gate is network-unaware and applies per site.
- A3 XML-RPC (`xmlrpc.php`) and REST auth are out of scope. They are separate attack surfaces and can be added later.
- A4 `wp-login.php` is served at the site root or a subdirectory. The plugin matches on the basename of the executed script.
- A5 The web server sets `SCRIPT_FILENAME` or `SCRIPT_NAME` for PHP requests (standard for Apache mod_php, php-fpm with nginx `fastcgi_params`).
- A6 Public posts with a password submit to `wp-login.php?action=postpass`. This flow only sets a cookie and redirects, so it is exempt (AC-9). Decided here, not asked.

## Assumptions and open questions

- Q1 Is the site behind a reverse proxy or CDN? If so, which address does `REMOTE_ADDR` show? Until answered, the plugin uses `REMOTE_ADDR` only.
- Q2 Should `xmlrpc.php` also be gated? Default: no, not in this version.
- Q3 Should a denied attempt be logged? Default: no logging in this version.

## Dependencies

- WordPress Settings API, options API, `wp_die`, `add_action`. All core.
- PHP `inet_pton`, `filter_var`. Core.

## Out of scope

- Two-factor authentication, login rate limiting, honeypots, XML-RPC and REST gating, multisite network admin, IP geolocation, request logging, and any remote management service.

## Success criteria

- SC-1 An IP not on the allowlist gets 403 for `/wp-admin/` and `wp-login.php`. Measured by the test suite and the manual checklist.
- SC-2 An allowlisted IP reaches both paths with no change in behavior.
- SC-3 Saving an allowlist that excludes the current admin IP is rejected with an error message. Measured by the settings sanitize test.
- SC-4 `admin-ajax.php` responds for non-allowlisted IPs.
- SC-5 All automated checks in plan.md's CI/CD section pass.

## Acceptance criteria

- AC-1 Given allowlist `203.0.113.0/24` and client `198.51.100.7`, a request to `/wp-admin/index.php` returns 403.
- AC-2 Given the same allowlist and client `203.0.113.9`, the same request is passed through.
- AC-3 When the executed script is `wp-admin/*.php` or `wp-login.php`, the request is gated, whatever the URI says. `/wp-login.php/x` (PATH_INFO) executes `wp-login.php` and is gated.
- AC-4 When the executed script is `wp-admin/admin-ajax.php`, the request is not gated.
- AC-9 `wp-login.php?action=postpass` is not gated (password-protected posts).
- AC-5 Given an empty allowlist, nothing is blocked and the settings page shows a warning.
- AC-6 Given an IPv4-mapped IPv6 client (`::ffff:203.0.113.9`) and an IPv4 rule, the match succeeds.
- AC-7 Saving a list without the current IP returns a settings error and the stored option does not change.
- AC-8 Constant-defined entries match even when the database option is empty.
