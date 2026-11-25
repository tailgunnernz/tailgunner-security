<?php
/**
 * Plugin Name:       Tailgunner Security
 * Plugin URI:        https://github.com/tailgunnernz/tailgunner-security
 * Description:       Tailgunner's baseline for every site we look after: object cache guards, minor-only core updates, forced two-factor, hardening, security headers, a scanner block and a signed health check for monitor.tailgunner.co.nz.
 * Version:           1.0.3
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Tailgunner
 * Author URI:        https://tailgunner.co.nz
 * License:           GPL-2.0-or-later
 * Text Domain:       tailgunner-security
 */

defined( 'ABSPATH' ) || exit;

define( 'TG_SECURITY_FILE', __FILE__ );

// The mu-plugin loader normally includes this already; this covers the first
// request after activation and any site where the loader can't be written.
require_once __DIR__ . '/early.php';
require_once __DIR__ . '/includes/loader.php';
require_once __DIR__ . '/includes/updater.php';

register_activation_hook( __FILE__, 'tg_security_activate' );
register_deactivation_hook( __FILE__, 'tg_security_remove_loader' );

add_action( 'init', 'tg_security_maybe_install_loader' );
