# plan.md: WP Admin Guard

Authority: `intent.md` is the source of requirements. This file covers how to build and verify them.

## Implementation overview

Two files hold logic. `includes/rules.php` contains pure functions with no WordPress calls: executed-script detection, CIDR matching, and allowlist parsing. Pure functions are testable with plain PHP. `wp-admin-guard.php` is the WordPress glue: hooks, options, settings page, and the 403 response. Tests load `rules.php` directly and `wp-admin-guard.php` with stubbed WordPress functions.

The gate keys on the executed file (`SCRIPT_FILENAME`), not on the request URI. An earlier version parsed and normalized the URI. Review found two bypasses: `/wp-login.php/x` (PATH_INFO) and a double-encoded path that the normalizer decoded into the `admin-ajax.php` exemption. Both come from the URI and the server disagreeing about what runs. Deleting the URI parser removes that class of bug.

## Affected components

New plugin directory `/opt/wp-admin-guard/`:

- `wp-admin-guard.php`: plugin header, `init` gate, activation hook, settings page, sanitize callback.
- `includes/rules.php`: pure logic.
- `uninstall.php`: deletes the `wpag_allowed` option.
- `tests/run.php`: assertion-based tests for `rules.php`.
- `readme.txt`: install, recovery, and reverse-proxy notes.

No existing repo is touched.

## Step-by-step implementation tasks

1. Write `includes/rules.php`:
   - `wpag_script_parts(string $file): array` returns lowercase basename and parent directory name, normalizing Windows separators.
   - `wpag_is_protected_script(string $file): bool` returns true for `wp-login.php` and for any script whose parent directory is `wp-admin`, except `admin-ajax.php`.
   - `wpag_is_login_script(string $file): bool` for the postpass exemption.
   - `wpag_normalize_ip(string $ip): ?string` maps `::ffff:a.b.c.d` to IPv4 and returns null for invalid input.
   - `wpag_ip_in_cidr(string $ip, string $cidr): bool` compares packed bytes under a prefix mask. Mixed family returns false.
   - `wpag_parse_rules(string $text): array{valid: string[], invalid: string[]}` splits on newlines and commas, trims, and validates each entry.
   - `wpag_ip_allowed(string $ip, array $rules): bool`.
2. Write `wp-admin-guard.php`:
   - Header, `ABSPATH` guard, `require` rules.
   - `init` gate (priority 0). Returns early if `WPAG_DISABLED` is true, if the executed script is not protected (falls back to `SCRIPT_NAME`), or for `wp-login.php?action=postpass`. Gets allowlist from `WPAG_ALLOWED_IPS` (constant, optional) plus `get_option('wpag_allowed', '')`. Empty combined list means fail open. Otherwise, a non-allowed `REMOTE_ADDR` gets `status_header(403)`, a plain-text body, and `exit`.
   - Activation hook: if `wpag_allowed` is empty, save the activating user's `REMOTE_ADDR` as `/32` or `/128`.
   - Settings page under Settings > WP Admin Guard, using the Settings API (`register_setting`, `add_settings_section`, `add_settings_field`), so nonce and capability checks come from core.
   - Sanitize callback: parse the textarea, drop invalid entries with a notice, and reject the save with `add_settings_error` if the current admin's IP is not covered by the combined rules. On rejection, return the previous option value.
   - Show current IP, constant-defined entries (read-only), and an empty-list warning.
3. Write `uninstall.php`: `delete_option('wpag_allowed')`, guarded by `WP_UNINSTALL_PLUGIN`.
4. Write `tests/run.php` covering every acceptance criterion that does not need WordPress.
5. Write `readme.txt` with install steps, recovery (`WPAG_DISABLED`, `WPAG_ALLOWED_IPS`, `wp option delete wpag_allowed`), and the reverse-proxy warning.

## Testing strategy

Automated (runs without WordPress):

- Unit tests for every `rules.php` function, including the IPv4-mapped case in AC-6 and protected/unprotected script names.
- Glue tests (`tests/glue.php`) run the gate with `SCRIPT_FILENAME` set to `wp-login.php` with PATH_INFO, `admin-post.php`, and `admin-ajax.php`, and the postpass action. Deny cases run in a child process because `exit` ends the process. A negative control confirms an unprotected script prints `NOT BLOCKED`.
- Negative cases: invalid CIDR prefix (`/33` for IPv4, `/129` for IPv6), empty string, garbage IP, mixed families.

Manual (requires a WordPress install, not available on this host):

- Install on a local WP 6.x site. Confirm AC-1 and AC-2 with curl using `--header 'X-Forwarded-For'` (should have no effect) and a source IP change.
- Confirm AC-4 by loading a public page that uses `admin-ajax.php` from a blocked IP.
- Confirm AC-7 by saving an allowlist without the current IP in the browser.

## Security protocols

- Client IP from `REMOTE_ADDR` only (NFR-1).
- Gate keys on the executed script, not the URI (NFR-2). No URI parsing, so no decode or normalization bypasses.
- Settings save requires `manage_options` and nonce (NFR-3). Core Settings API enforces both. Do not add a custom form handler.
- All output escaped with `esc_html`, `esc_attr`, `esc_textarea`.
- No secrets stored. The allowlist is not sensitive, but it is admin-only data.
- The 403 body does not reveal the allowlist or the rule that matched.

## Documentation requirements

- `readme.txt` must cover: install, recovery paths, reverse proxy caveat (Q1), the `admin-ajax.php` exemption, and the fail-open behavior on an empty list.
- Behavior change is user-visible, so the readme is required, not optional.

## CI/CD validation

No CI config exists in `/opt/wp-admin-guard/`, and no repo is set up. These gates are described so they can be wired into any pipeline. Each runs locally with the commands given. Ordered as the skill requires.

| # | Gate | Command | Mandatory | Fails when |
|---|------|---------|-----------|------------|
| 1 | Spec validation | `test -f intent.md && test -f plan.md` | y | either file is missing |
| 2 | Build | none (no build step) | n | n/a |
| 3 | Lint (syntax) | `find . -name '*.php' -print0 \| xargs -0 -n1 php -l` | y | any file reports a syntax error |
| 4 | Type-check | none (no static types beyond PHP 7.4 hints) | n | n/a |
| 5 | Unit and glue tests | `php tests/run.php && php tests/glue.php` | y | any assertion fails, exit code nonzero |
| 6 | Integration tests | manual WP checklist below | y before release | any checklist item fails |
| 7 | Static security analysis | `phpstan` or `psalm` at level 5 with WordPress stubs, not yet installed | y once installed | a new finding (tooling not available here) |
| 8 | Dependency scan | n/a, no dependencies | n | n/a |
| 9 | Coverage gate | n/a, rules.php coverage tracked by test count against the function list | n | a `rules.php` function has no test (checked by review) |
| 10 | Acceptance criteria | every AC-1..AC-8 maps to a test or checklist item (traceability table) | y | an AC has no mapped test |

Gate 7 is not installed here, so it is listed as required once installed. Until then, this gate is unverified, and any release must say so.

Manual WordPress checklist (gate 6):

0. Confirm the target server sets `SCRIPT_FILENAME` or `SCRIPT_NAME` for PHP (for example with `<?php var_dump($_SERVER['SCRIPT_FILENAME']);` in a temp file). If neither is set the gate never fires, so this must pass first.
1. Activate on a fresh WP 6.x install from an allowed IP. Confirm `wpag_allowed` is set to the current IP.
2. From a non-allowed IP, `GET /wp-admin/` returns 403. `GET /wp-login.php` returns 403. `GET /wp-login.php/x` (PATH_INFO) returns 403. `GET /wp-admin/admin-post.php` returns 403.
3. From an allowed IP, both return normal responses.
4. Frontend page that calls `admin-ajax.php` still works from a non-allowed IP. A password-protected post can be unlocked from a non-allowed IP (postpass).
5. Settings page: save an allowlist without the current IP. Expect the error and no change.
6. Clear the option with `wp option delete wpag_allowed`. Confirm the site fails open and the warning appears.
7. Define `WPAG_DISABLED` in `wp-config.php`. Confirm no gating.
8. Define `WPAG_ALLOWED_IPS` with the current IP and an empty option. Confirm access and that the settings page lists the constant.

## Rollout and deployment

- Install on staging first. Run checklist items 1 to 8.
- Enable on production only after the owner confirms Q1 (reverse proxy). Keep `WPAG_DISABLED` documented as the emergency switch.

## Rollback strategy

- Deactivate or delete the plugin folder. Gating stops immediately because it runs on `init`.
- If the plugin is unreachable but still active, set `define('WPAG_DISABLED', true);` in `wp-config.php`, which needs only file access.
- Uninstall deletes the option. Nothing else is written to the database.

## Requirement traceability

| Requirement | Implementation task | Test / validation |
|---|---|---|
| FR-1 gate by IP | Step 2 `init` gate | Unit: `wpag_ip_allowed`, `wpag_is_protected_script`; glue: deny child; checklist 2, 3 |
| FR-2 settings page | Step 2 settings | Checklist 5 |
| FR-3 lockout safety | Step 2 sanitize callback | AC-7; checklist 5 |
| FR-4 IP and CIDR | Step 1 `wpag_parse_rules`, `wpag_ip_in_cidr` | Unit: parse and CIDR cases |
| FR-5 admin-ajax exempt | Step 1 `wpag_is_protected_script` | AC-4 unit; glue: gate exempts admin-ajax; checklist 4 |
| FR-6 admin-post gated | Step 1 `wpag_is_protected_script` | Unit: `admin-post.php` protected; glue: admin-post deny child |
| FR-7 403 generic body | Step 2 gate response | Checklist 2 (body inspected) |
| FR-8 activation adds current IP | Step 2 activation hook | Checklist 1 |
| FR-9 constant allowlist | Step 2 gate reads `WPAG_ALLOWED_IPS` | AC-8; checklist 8 |
| FR-10 kill switch | Step 2 gate checks `WPAG_DISABLED` | Checklist 7 |
| NFR-1 REMOTE_ADDR only | Step 2 gate | Checklist 2 (XFF header sent, no effect) |
| NFR-2 executed-script keying | Step 2 gate reads `SCRIPT_FILENAME` | Glue: PATH_INFO deny child; checklist 0, 2 |
| NFR-3 capability and nonce | Step 2 Settings API | Checklist 5 |
| NFR-4 WP 6.0+, PHP 7.4+ | Step 1 syntax, no 8.x-only features | Gate 3 run on PHP 8.5 only; 7.4 not verified here (open) |
| NFR-5 no extra queries off protected paths | Step 2 path check before option read | Code review |
| NFR-6 fail open on empty list | Step 2 gate, settings warning | AC-5 unit (`wpag_ip_allowed` with empty list returns false, gate treats empty as open) |
| NFR-7 no network calls | Whole plugin | Code review |
| AC-1 | Gate | Unit + checklist 2 |
| AC-2 | Gate | Unit + checklist 3 |
| AC-3 | `wpag_is_protected_script` | Unit + glue PATH_INFO deny; checklist 2 |
| AC-4 | `wpag_is_protected_script` | Unit + glue + checklist 4 |
| AC-9 | Gate postpass exemption | Glue: gate exempts postpass; checklist 4 |
| AC-5 | Gate + warning | Unit + checklist 6 |
| AC-6 | `wpag_normalize_ip` | Unit |
| AC-7 | Sanitize callback | Checklist 5 |
| AC-8 | Constant merge | Checklist 8 |

Open items that block the traceability from being fully verified: NFR-4 on PHP 7.4 (not installed here) and gate 7 (static analysis, not installed).

## Definition of done

- All unit tests in `tests/run.php` pass, with the output shown.
- Every gate 1 to 5 and 10 passes locally.
- Checklist 1 to 8 run on a WordPress install and each result is recorded in the review section.
- Open items above are either closed or stated in the handoff.

## Review results

Run on PHP 8.5.4 CLI (Ubuntu package), 2026-11-07:

- Gate 3 (`php -l`) on all five PHP files: no syntax errors.
- Gate 5: `php tests/run.php` 52 passed, 0 failed. `php tests/glue.php` 18 passed, 0 failed. The glue suite stubs WordPress core functions and runs deny paths in child processes, which confirms the 403 status and "Forbidden" body. A negative control (`php tests/glue.php deny /var/www/html/index.php`) prints `NOT BLOCKED`.
- Advisor review found two URI-based bypasses (PATH_INFO on wp-login, over-decoding into the admin-ajax exemption). Both reproduced with the old normalizer. The gate was rewritten to key on `SCRIPT_FILENAME`, and the URI parser was deleted. The suites above run against the new gate.
- Gate 10: every AC-1..AC-8 maps to a passing unit or glue case, or to a checklist item still to run (see traceability table).

Not verified:

- Checklist 1 to 8 (gate 6): no WordPress install on this host. Not run.
- Gate 7: no static analyzer installed. Not run.
- NFR-4 PHP 7.4: only PHP 8.5 is installed. Syntax was checked by reading for 8.x-only features (none used), but not by running 7.4.
- Q1 (reverse proxy): unanswered. The plugin uses REMOTE_ADDR only.

## Plugin Check fixes (rev 2)

Source: Plugin Check report, 2026-11-07 20:17. Findings and decisions:

| Finding | Decision | Verified by |
|---|---|---|
| Name and slug contain restricted term "wp" | Rename to Admin Area IP Guard, slug `admin-area-ip-guard`, main file `admin-area-ip-guard.php`, text domain `admin-area-ip-guard`. Option and constant prefix `wpag` stays (4-char prefix, not a restricted term). | grep for `wp-admin-guard` and `WP Admin Guard` returns nothing outside history; glue suite requires the new filename |
| Missing direct-access guard | Shipped PHP uses `if (!defined('ABSPATH')) exit;`. Tests define `ABSPATH` before loading. | Plugin Check rerun |
| `$_SERVER` read without unslash/sanitize | `sanitize_text_field( wp_unslash( ... ) )` for REMOTE_ADDR, SCRIPT_FILENAME, SCRIPT_NAME | unit tests for helper behavior unchanged; Plugin Check rerun |
| Nonce warning on `$_REQUEST` | Read `$_GET['action']` (postpass uses the query string) with a documented phpcs ignore. Read-only routing check, no state change. | glue test for postpass exemption |
| Tests flagged in release | `tests/` excluded from release ZIP. Stays in repo. | `unzip -l` on built ZIP |
| Readme Tested up to 6.8 | Already 7.1 in source. Stale ZIP was the cause. Rebuild. | `unzip -p` on built ZIP |

Build: `dist/build-zip.sh` creates `dist/admin-area-ip-guard.zip` with a single root folder `admin-area-ip-guard/`. Excludes tests, specs, HOWTO, dist.

Documentation changes: readme, HOWTO, submission draft, and svn script use the new name. The old `wp-admin-guard.zip` is removed.
