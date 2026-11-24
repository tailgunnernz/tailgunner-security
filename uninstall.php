<?php
/**
 * Removes the loader and everything the plugin stored.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$tg_security_loader = WPMU_PLUGIN_DIR . '/0-tailgunner-security.php';

if ( is_file( $tg_security_loader ) && false !== strpos( (string) file_get_contents( $tg_security_loader ), 'TG_SECURITY_LOADER' ) ) {
	@unlink( $tg_security_loader );
}

if ( is_file( $tg_security_loader . '.off' ) ) {
	@unlink( $tg_security_loader . '.off' );
}

delete_option( 'tg_security_state' );
delete_option( 'tg_security_two_factor_start' );
delete_option( 'tg_security_health_last' );
delete_option( 'tg_security_cron_last' );
delete_transient( 'tg_security_loader_failed' );
