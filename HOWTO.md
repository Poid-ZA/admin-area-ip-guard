# Admin Area IP Guard: the simple guide

## What does it do?

It puts a lock on your WordPress admin door.

Only computers on a list you choose can open the admin login page and the admin screens. Everyone else gets a "Forbidden" message.

Visitors to your normal website are not affected.

## Before you start

You need:

- A WordPress website (version 6.0 or newer).
- An administrator login.
- The file `admin-area-ip-guard.zip`.
- Your current internet address. You can find it on the plugin's settings page once it is installed. It is the "Your current address" line.

## Step 1: Install the plugin

1. Log in to your WordPress admin.
2. Go to **Plugins > Add New Plugin > Upload Plugin**.
3. Choose `admin-area-ip-guard.zip` and click **Install Now**.
4. Click **Activate Plugin**.

When you activate it, the plugin adds your current address to the list. That keeps you from locking yourself out.

## Step 2: Add the addresses you want to allow

1. Go to **Settings > Admin Area IP Guard**.
2. Type one address per line in the box.
   - One computer: `203.0.113.9`
   - A whole network: `203.0.113.0/24`
3. Click **Save Changes**.

The plugin refuses to save a list that leaves out your current address. If you see "Not saved", add your address and try again.

## Step 3: Test it

1. Open your site's admin page from the allowed computer. It should work as normal.
2. Open the same page from a phone on mobile data, or ask a friend on another network. They should see "Forbidden".

If that works, the lock is set.

## Something went wrong, and I am locked out

Do not panic. Use one of these fixes. Each needs access to your website files or your hosting control panel.

**Option A: Add your address in wp-config.php**

Open `wp-config.php` in the main WordPress folder. Add this line above the line that says `/* That's all, stop editing! */`:

```php
define('WPAG_ALLOWED_IPS', array('203.0.113.9'));
```

Replace `203.0.113.9` with your address. Your address is always allowed while this line is there.

**Option B: Turn the lock off**

Add this line above the same line in `wp-config.php`:

```php
define('WPAG_DISABLED', true);
```

Remove it once you have fixed the list. The plugin stays installed.

**Option C: Clear the list**

If you have WP-CLI installed, run:

```
wp option delete wpag_allowed
```

An empty list means nothing is locked.

## Good to know

- **Public pages still work.** Only the admin login and admin screens are locked.
- **Password-protected posts still work.** Visitors can still type in the post password.
- **Your address might look different.** If your site is behind Cloudflare or another proxy, the plugin sees the proxy's address, not the visitor's. Check the address on the settings page before you trust the list.
- **Deleting the plugin removes its list** from your database.

## Want to check the code?

The plugin is short. Open `admin-area-ip-guard.php` for the main logic and `includes/rules.php` for the address matching.

To run the automatic tests, you need PHP on your computer:

```
php tests/run.php
php tests/glue.php
```

Both should end with a line that says the number of passed tests and no failures.
