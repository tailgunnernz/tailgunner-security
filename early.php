<?php
/**
 * Loads every feature and wires up its hooks.
 *
 * wp-content/mu-plugins/0-tailgunner-security.php includes this file before
 * any normal plugin loads. That lets the option cache guard repair
 * active_plugins before WordPress reads it, and keeps everything running
 * while WordPress has the plugin silently deactivated during an update.
 * If the loader is missing, the main plugin file includes this instead.
 *
 * The feature files only define functions. Every hook is added here.
 */

defined( 'ABSPATH' ) || exit;

if ( defined( 'TG_SECURITY_VERSION' ) ) {
	return;
}

define( 'TG_SECURITY_VERSION', '1.0.0' );
define( 'TG_SECURITY_DIR', __DIR__ . '/' );

require TG_SECURITY_DIR . 'includes/common.php';
require TG_SECURITY_DIR . 'includes/option-guard.php';
require TG_SECURITY_DIR . 'includes/acf-guard.php';
require TG_SECURITY_DIR . 'includes/scanner-block.php';
require TG_SECURITY_DIR . 'includes/update-policy.php';
require TG_SECURITY_DIR . 'includes/two-factor.php';
require TG_SECURITY_DIR . 'includes/hardening.php';
require TG_SECURITY_DIR . 'includes/headers.php';
require TG_SECURITY_DIR . 'includes/mail-log.php';
require TG_SECURITY_DIR . 'includes/health.php';

// Reliability.
foreach ( tg_security_option_guard_names() as $tg_security_option ) {
	add_filter( "default_option_{$tg_security_option}", 'tg_security_option_guard', 10, 3 );
}
unset( $tg_security_option );
add_filter( 'validate_current_theme', 'tg_security_validate_theme_guard', PHP_INT_MAX );

// acf/init fires inside ACF's own init, after WPML has set the language its
// cache keys use and before ACF registers post types and taxonomies.
add_action( 'acf/init', 'tg_security_acf_guard', 1 );

// Scanner block. It waits for muplugins_loaded so another mu-plugin can turn
// it off with the tg_security_feature_enabled filter.
if ( did_action( 'muplugins_loaded' ) ) {
	tg_security_scanner_check();
} else {
	add_action( 'muplugins_loaded', 'tg_security_scanner_check', 0 );
}

// Core updates: minor releases only, whatever else on the site says.
add_filter( 'automatic_updater_disabled', 'tg_security_updater_disabled', PHP_INT_MAX );
add_filter( 'allow_dev_auto_core_updates', 'tg_security_allow_dev_core', PHP_INT_MAX );
add_filter( 'allow_minor_auto_core_updates', 'tg_security_allow_minor_core', PHP_INT_MAX );
add_filter( 'allow_major_auto_core_updates', 'tg_security_allow_major_core', PHP_INT_MAX );
add_filter( 'auto_update_core', 'tg_security_auto_update_core', PHP_INT_MAX, 2 );
add_filter( 'auto_update_plugin', 'tg_security_frozen_plugin_updates', PHP_INT_MAX, 2 );
add_filter( 'auto_update_theme', 'tg_security_frozen_theme_updates', PHP_INT_MAX, 2 );
add_filter( 'plugins_auto_update_enabled', 'tg_security_frozen_toggles', PHP_INT_MAX );
add_filter( 'themes_auto_update_enabled', 'tg_security_frozen_toggles', PHP_INT_MAX );

// Two-factor (needs the Two Factor plugin).
add_filter( 'two_factor_enabled_providers_for_user', 'tg_security_force_two_factor', 10, 2 );
add_filter( 'two_factor_primary_provider_for_user', 'tg_security_two_factor_primary', 10, 2 );
add_action( 'admin_notices', 'tg_security_two_factor_notice' );

// Hardening.
add_action( 'plugins_loaded', 'tg_security_hardening_early', PHP_INT_MAX );
add_action( 'template_redirect', 'tg_security_block_author_scan', 0 );
add_filter( 'rest_pre_dispatch', 'tg_security_block_rest_users', 10, 3 );
add_filter( 'wp_sitemaps_add_provider', 'tg_security_no_user_sitemap', 10, 2 );
add_filter( 'option_default_role', 'tg_security_safe_default_role' );
add_filter( 'the_generator', 'tg_security_hide_generator' );
add_filter( 'wp_headers', 'tg_security_remove_pingback_header' );

// Security headers.
add_action( 'send_headers', 'tg_security_front_headers' );
add_action( 'admin_init', 'tg_security_admin_headers' );
add_action( 'login_init', 'tg_security_admin_headers' );
add_filter( 'rest_post_dispatch', 'tg_security_rest_headers' );

// Monitoring.
add_action( 'wp_mail_failed', 'tg_security_mail_failed' );
add_action( 'wp_loaded', 'tg_security_health_maybe_serve', 0 );
if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
	add_action( 'shutdown', 'tg_security_cron_heartbeat' );
}
