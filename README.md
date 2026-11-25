# Tailgunner Security

The baseline plugin for every WordPress site Tailgunner looks after, on any host. It has no settings screen: every site gets the same behaviour, and updates arrive from GitHub releases.

## What it does

**Reliability**
- **Option cache guard.** When a persistent object cache records a core option (`template`, `active_plugins`, `siteurl`, `cron`, user roles and others) as missing after a database outage, it checks the database and reloads the options cache. If the database can't answer, visitors get a 503 (not cached) instead of a blank page. WordPress's switch to a default theme on the Themes screen is skipped while the theme options disagree with the database.
- **ACF cache guard.** Clears an empty cached list of ACF field groups, post types, taxonomies or options pages when the posts exist.
- **Core updates.** Maintenance and security releases install automatically, major releases never do, whatever wp-config or an mu-plugin says. `DISALLOW_FILE_MODS` is respected.

**Security**
- **Forced two-factor** for anyone who can manage the site, edit others' content or run the shop. Users without an authenticator app or passkey get emailed codes. Needs the [Two Factor](https://wordpress.org/plugins/two-factor/) plugin.
- **Pending 2FA logins stay pending** on Two Factor 0.8.0 to 0.16.0 (0.17.0 has the fix but needs WordPress 7.0; 0.7.x and older aren't covered): a wrong login nonce sent to `wp-login.php?action=validate_2fa` is turned away without deleting the user's pending one, as Two Factor 0.17.0 does (CVE-2026-100508).
- **Hardening.** XML-RPC off (unless Jetpack is connected), file editor off, no username listing for logged-out visitors (`?author=N`, `/wp-json/wp/v2/users`, users sitemap), no privileged default role for registrations, no WordPress version in the generator tag.
- **Security headers.** HSTS (1 day, no includeSubDomains or preload), `X-Content-Type-Options`, `Referrer-Policy`, and `X-Frame-Options: SAMEORIGIN` on front-end pages. No Content-Security-Policy.
- **Scanner block.** The rules from our `.htaccess` scanner block, in PHP, so sites on nginx, Lightning or other hosts get them too.

**Monitoring**
- **Health check** for monitor.tailgunner.co.nz: signed POST to `/?tailgunner-health`, answered with JSON about core settings, theme, guard heals, mail failures, privileged accounts (anyone who can change settings, users, plugins or themes, plus a hash of the role definitions, for the monitor to diff), two-factor coverage, cron, updates and update settings.
- **Mail failure log.** Every send WordPress reports as failed is recorded for the health check, so the monitor alerts instead of the site's own (broken) mail. Email addresses in errors are cut down to their domain.

## How it loads

On activation the plugin writes `wp-content/mu-plugins/0-tailgunner-security.php`, a short loader that includes `early.php` from the plugin folder before other plugins load. That way the option guard can repair `active_plugins`, and everything keeps running while WordPress has the plugin silently deactivated during an update. The plugin rewrites the loader if it goes missing. Deactivating the plugin (from wp-admin, wp-cli or anything else) removes the loader and leaves `0-tailgunner-security.php.off`, so it isn't rewritten until the plugin is activated again. If the plugin drops out of `active_plugins` any other way while the loader is still there (a stale object cache overwriting the list, say), the loader puts it back, at most once an hour, and the health check reports `reactivated_24h`. A fatal error inside the plugin's files is caught by the loader and logged instead of taking the site down, as far as PHP allows.

**Emergency off switch:** delete `wp-content/plugins/tailgunner-security` over SFTP or SSH. The leftover loader then does nothing.

## Exceptions

There are no per-site settings. If a site needs a feature off, add an mu-plugin:

```php
add_filter( 'tg_security_feature_enabled', function ( $on, $feature ) {
	return 'headers' === $feature ? false : $on;
}, 10, 2 );
```

Features: `option_guard`, `acf_guard`, `scanner_block`, `update_policy`, `two_factor`, `two_factor_nonce`, `xmlrpc`, `file_editor`, `user_enumeration`, `default_role`, `hide_version`, `headers`, `mail_log`, `health`.

## Health check protocol

The monitor sends `POST https://<site>/?tailgunner-health` with body `{"host":"<site host>","ts":<unix time in ms>}` and header `X-Tailgunner-Signature: <base64 Ed25519 signature of the exact body>`. The plugin holds only the public key (`includes/health.php`); the private key is the monitor's `TG_HEALTH_SIGNING_KEY` secret. A request is refused (403 with `{"error": "<reason>"}`) unless the signature verifies, the timestamp is within 5 minutes and newer than the last accepted one, and the host matches the site.

`dev/health.sh <url>` signs and sends a check from this Mac using the key in `../uptime-monitor/.dev.vars`.

## Releasing

1. Bump `Version:` in `tailgunner-security.php` and `TG_SECURITY_VERSION` in `early.php`.
2. Test on tailgunner.co.nz (`dev/` has the test scripts).
3. Push to main, then publish a GitHub release with a matching tag (`v1.2.0` or `1.2.0`). The workflow lints and smoke-loads on PHP 7.4 and 8.4, then attaches `tailgunner-security.zip`. Sites only take that zip, never the tag's source archive.

Every release auto-installs on every site on the next cron run. Mark a release as a pre-release to hold it back.
